import json
import os
import subprocess
import tempfile
from collections import Counter
from sensors.passive import run_passive_sensors
from engine.assessment import build_assessment

def run(command):
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


def tshark_fields(pcap, display_filter, fields):
    """
    Читает pcap через tshark и возвращает список строк.

    Например:
        vlan.id
        eth.src
        arp.src.proto_ipv4
    """

    command = [
        "tshark",
        "-r", pcap,
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=a"
    ]

    for field in fields:
        command += ["-e", field]

    output = run(command)

    if not output:
        return []

    rows = []

    for line in output.splitlines():

        columns = line.split("\t")

        while len(columns) < len(fields):
            columns.append("")

        rows.append(columns)

    return rows


def count_frames(pcap, display_filter):
    command = [
        "tshark",
        "-r", pcap,
        "-Y", display_filter,
        "-T", "fields",
        "-e", "frame.number"
    ]

    output = run(command)

    if not output:
        return 0

    return len(output.splitlines())


def capture(interface, duration):

    fd, path = tempfile.mkstemp(
        prefix="wirescope_",
        suffix=".pcap"
    )

    os.close(fd)

    command = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{duration}",
        "-w", path,
        "-q"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False
    )

    if result.returncode != 0:

        try:
            os.remove(path)
        except OSError:
            pass

        raise RuntimeError(
            f"tshark capture failed: "
            f"{result.stderr.strip()}"
        )

    return path

def parse_vlans(pcap):

    rows = tshark_fields(
        pcap,
        "vlan",
        ["vlan.id"]
    )

    vlans = Counter()

    for row in rows:

        value = row[0]

        if not value:
            continue

        # QinQ может дать несколько VLAN ID
        for vlan in value.split(","):

            vlan = vlan.strip()

            if vlan.isdigit():
                vlans[int(vlan)] += 1

    return [
        {
            "id": vlan,
            "frames": count
        }
        for vlan, count
        in sorted(vlans.items())
    ]


def parse_arp(pcap):

    rows = tshark_fields(
        pcap,
        "arp",
        [
            "arp.src.proto_ipv4",
            "arp.src.hw_mac"
        ]
    )

    devices = {}

    for ip, mac in rows:

        if not ip or not mac:
            continue

        devices[ip] = mac

    return [
        {
            "ipv4": ip,
            "mac": mac
        }
        for ip, mac in sorted(devices.items())
    ]


def parse_lldp(pcap):

    rows = tshark_fields(
        pcap,
        "lldp",
        [
            "lldp.tlv.system.name",
            "lldp.port.id"
        ]
    )

    neighbors = []

    seen = set()

    for system_name, port_id in rows:

        key = (system_name, port_id)

        if key in seen:
            continue

        seen.add(key)

        neighbors.append({
            "system_name": system_name or None,
            "port_id": port_id or None
        })

    return neighbors


def parse_cdp(pcap):

    rows = tshark_fields(
        pcap,
        "cdp",
        [
            "cdp.deviceid",
            "cdp.portid"
        ]
    )

    neighbors = []

    seen = set()

    for device, port in rows:

        key = (device, port)

        if key in seen:
            continue

        seen.add(key)

        neighbors.append({
            "device": device or None,
            "port": port or None
        })

    return neighbors


def parse_mac_addresses(pcap):

    rows = tshark_fields(
        pcap,
        "eth",
        ["eth.src"]
    )

    macs = Counter()

    for row in rows:

        mac = row[0].lower().strip()

        if mac:
            macs[mac] += 1

    return [
        {
            "mac": mac,
            "frames": count
        }
        for mac, count in macs.most_common()
    ]


def analyze_pcap(pcap):

    total_frames = count_frames(
        pcap,
        "frame"
    )

    sensors = run_passive_sensors(
        tshark_fields,
        count_frames,
        pcap
    )

    macs = parse_mac_addresses(pcap)

    detected_sensors = [
        name
        for name, result
        in sensors.items()
        if result["detected"]
    ]

    return {

        "capture": {
            "status": "completed",
            "frames": total_frames
        },

        "devices": {
            "mac_addresses": macs
        },

        "sensors": sensors,

        "summary": {
            "frames": total_frames,
            "mac_addresses": len(macs),
            "sensors_triggered": len(
                detected_sensors
            ),
            "detected": detected_sensors
        }
    }

def passive_discovery(interface, duration=20):

    pcap = capture(
        interface,
        duration
    )

    try:

        result = analyze_pcap(
            pcap
        )

        result["interface"] = interface
        result["duration_seconds"] = duration

        result["assessment"] = build_assessment(
            result
        )

        return result

    finally:

        try:
            os.remove(pcap)

        except OSError:
            pass

if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:

        print(
            "Usage: python passive.py <interface> [seconds]"
        )

        sys.exit(1)

    interface = sys.argv[1]

    duration = (
        int(sys.argv[2])
        if len(sys.argv) >= 3
        else 20
    )

    print(
        json.dumps(
            passive_discovery(
                interface,
                duration
            ),
            indent=2
        )
    )
