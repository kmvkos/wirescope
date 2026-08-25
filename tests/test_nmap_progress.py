from providers.nmap_progress import NmapProgressParser


def test_nmap_progress_parser_tracks_percent_hosts_and_open_ports_across_chunks():
    parser = NmapProgressParser()

    first = parser.feed(
        "stdout",
        "Discovered open port 443/tcp on 10.11.11.82\nDiscovered open po",
    )
    second = parser.feed(
        "stdout",
        "rt 22/tcp on 10.11.11.10\n",
    )
    stats = parser.feed(
        "stderr",
        "Stats: 0:00:10 elapsed; 2 hosts completed (10 up), 8 undergoing SYN Stealth Scan\n"
        "SYN Stealth Scan Timing: About 37.50% done; ETC: 16:14 (0:00:25 remaining)\n",
    )

    assert first[-1].open_ports == 1
    assert second[-1].open_ports == 2
    snapshot = stats[-1]
    assert snapshot.percent == 37.5
    assert snapshot.phase == "SYN Stealth Scan"
    assert snapshot.hosts_completed == 2
    assert snapshot.hosts_up == 10
    assert snapshot.open_ports == 2
    assert snapshot.last_open_port == 22
    assert snapshot.last_open_host == "10.11.11.10"
    assert snapshot.remaining == "0:00:25"


def test_nmap_progress_parser_deduplicates_repeated_open_port_messages():
    parser = NmapProgressParser()
    line = "Discovered open port 443/tcp on 10.11.11.82\n"
    parser.feed("stdout", line)
    parser.feed("stderr", line)

    assert parser.snapshot().open_ports == 1
