import json
import socket
import subprocess
from pathlib import Path


SYSTEMD_LEASE_DIR = Path("/run/systemd/netif/leases")
SYS_CLASS_NET = Path("/sys/class/net")


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=8,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def get_interface_speed(interface):
    path = Path(f"/sys/class/net/{interface}/speed")

    try:
        speed = path.read_text().strip()

        if speed.isdigit():
            return int(speed)

    except OSError:
        pass

    return None


def get_interfaces():
    output = run_command(["ip", "-j", "addr"])

    if not output:
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    interfaces = []

    for iface in data:
        name = iface.get("ifname")

        if name == "lo":
            continue

        item = {
            "name": name,
            "state": iface.get("operstate"),
            "mac": iface.get("address"),
            "mtu": iface.get("mtu"),
            "speed_mbps": get_interface_speed(name),
            "ipv4": [],
            "ipv6": []
        }

        for address in iface.get("addr_info", []):
            family = address.get("family")
            local = address.get("local")
            prefix = address.get("prefixlen")

            if not local:
                continue

            value = f"{local}/{prefix}"

            if family == "inet":
                item["ipv4"].append(value)

            elif family == "inet6":
                item["ipv6"].append(value)

        interfaces.append(item)

    return interfaces


def get_default_routes():
    """Return every IPv4 default route, preserving its owning interface.

    A multi-homed appliance may have several DHCP/default routes with different
    metrics.  Keeping only the kernel-preferred route loses topology evidence
    for the audit interface, so all rows are persisted.
    """
    output = run_command(["ip", "-j", "-4", "route", "show", "default"])
    if not output:
        return []
    try:
        routes = json.loads(output)
    except json.JSONDecodeError:
        return []

    result = []
    for route in routes:
        if not isinstance(route, dict):
            continue
        result.append(
            {
                "gateway": route.get("gateway"),
                "interface": route.get("dev"),
                "source_address": route.get("prefsrc") or route.get("src"),
                "metric": route.get("metric"),
                "protocol": route.get("protocol"),
            }
        )
    return result


def get_default_route():
    routes = get_default_routes()
    return routes[0] if routes else None


def get_routes():
    output = run_command(
        ["ip", "-j", "-4", "route"]
    )

    if not output:
        return []

    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return []


def _interface_by_ifindex(sys_class_net=SYS_CLASS_NET):
    result = {}
    try:
        entries = list(sys_class_net.iterdir())
    except OSError:
        return result
    for entry in entries:
        try:
            ifindex = (entry / "ifindex").read_text().strip()
        except OSError:
            continue
        if ifindex:
            result[ifindex] = entry.name
    return result


def _parse_key_value_file(path):
    result = {}
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return result
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip().upper()] = value.strip()
    return result


def get_systemd_dhcp_leases(lease_dir=SYSTEMD_LEASE_DIR, sys_class_net=SYS_CLASS_NET):
    """Read systemd-networkd DHCP lease state without generating network I/O."""
    by_index = _interface_by_ifindex(sys_class_net)
    try:
        paths = sorted(path for path in lease_dir.iterdir() if path.is_file())
    except OSError:
        return []

    leases = []
    for path in paths:
        values = _parse_key_value_file(path)
        interface = values.get("INTERFACE") or by_index.get(path.name) or by_index.get(values.get("IFINDEX", ""))
        if not interface:
            continue
        routers = values.get("ROUTER") or values.get("ROUTERS") or ""
        dns = values.get("DNS") or ""
        leases.append(
            {
                "interface": interface,
                "address": values.get("ADDRESS"),
                "routers": [value for value in routers.replace(",", " ").split() if value],
                "dns": [value for value in dns.replace(",", " ").split() if value],
                "server_address": values.get("SERVER_ADDRESS") or values.get("SERVER_IDENTIFIER"),
                "source": "systemd-networkd-lease",
            }
        )
    return leases


def _parse_nmcli_device(interface):
    """Best-effort NetworkManager DHCP evidence; no failure is fatal."""
    output = run_command(
        [
            "nmcli",
            "-t",
            "-f",
            "IP4.ADDRESS,IP4.GATEWAY,IP4.DNS,DHCP4.OPTION",
            "device",
            "show",
            interface,
        ]
    )
    if not output:
        return None

    addresses = []
    gateways = []
    dns = []
    server_address = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip().replace("\\:", ":")
        upper = key.upper()
        if upper.startswith("IP4.ADDRESS") and value:
            addresses.append(value)
        elif upper.startswith("IP4.GATEWAY") and value:
            gateways.append(value)
        elif upper.startswith("IP4.DNS") and value:
            dns.append(value)
        elif upper.startswith("DHCP4.OPTION") and "=" in value:
            option, option_value = [part.strip() for part in value.split("=", 1)]
            option = option.lower().replace("_", "-")
            if option in {"routers", "router"}:
                gateways.extend(part for part in option_value.replace(",", " ").split() if part)
            elif option in {"domain-name-servers", "domain-name-server"}:
                dns.extend(part for part in option_value.replace(",", " ").split() if part)
            elif option in {"dhcp-server-identifier", "server-identifier"}:
                server_address = option_value

    if not addresses and not gateways and not dns and not server_address:
        return None
    return {
        "interface": interface,
        "address": addresses[0] if addresses else None,
        "routers": list(dict.fromkeys(gateways)),
        "dns": list(dict.fromkeys(dns)),
        "server_address": server_address,
        "source": "networkmanager-dhcp",
    }


def get_dhcp_leases(interfaces=None):
    """Collect local DHCP configuration evidence without sending DHCP packets."""
    result = get_systemd_dhcp_leases()
    seen = {str(item.get("interface")) for item in result}
    for item in interfaces or get_interfaces():
        interface = str(item.get("name") or "") if isinstance(item, dict) else str(item or "")
        if not interface or interface in seen:
            continue
        lease = _parse_nmcli_device(interface)
        if lease:
            result.append(lease)
            seen.add(interface)
    return result


def get_dns():
    servers = []

    try:
        with open("/etc/resolv.conf") as file:
            for line in file:
                line = line.strip()

                if line.startswith("nameserver"):
                    parts = line.split()

                    if len(parts) >= 2:
                        servers.append(parts[1])

    except OSError:
        pass

    return servers


def get_environment():
    interfaces = get_interfaces()
    default_routes = get_default_routes()
    return {
        "hostname": socket.gethostname(),
        "interfaces": interfaces,
        "default_route": default_routes[0] if default_routes else None,
        "default_routes": default_routes,
        "routes": get_routes(),
        "dhcp_leases": get_dhcp_leases(interfaces),
        "dns": get_dns()
    }


if __name__ == "__main__":
    print(json.dumps(
        get_environment(),
        indent=2
    ))
