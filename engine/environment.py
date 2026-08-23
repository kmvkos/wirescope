import json
import socket
import subprocess
from pathlib import Path


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
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

    data = json.loads(output)
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


def get_default_route():
    output = run_command(
        ["ip", "-j", "route", "show", "default"]
    )

    if not output:
        return None

    routes = json.loads(output)

    if not routes:
        return None

    route = routes[0]

    return {
        "gateway": route.get("gateway"),
        "interface": route.get("dev")
    }


def get_routes():
    output = run_command(
        ["ip", "-j", "-4", "route"]
    )

    if not output:
        return []

    return json.loads(output)


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
    return {
        "hostname": socket.gethostname(),
        "interfaces": get_interfaces(),
        "default_route": get_default_route(),
        "routes": get_routes(),
        "dns": get_dns()
    }


if __name__ == "__main__":
    print(json.dumps(
        get_environment(),
        indent=2
    ))
