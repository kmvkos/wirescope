from providers.bpf import BpfFilterError, normalize_bpf_filter


def test_empty_filter_means_capture_everything():
    assert normalize_bpf_filter(None) is None
    assert normalize_bpf_filter("  ") is None
    assert normalize_bpf_filter("\t") is None


def test_valid_tcpdump_filters_are_normalized():
    assert normalize_bpf_filter(" tcp  port   80 ") == "tcp port 80"
    assert (
        normalize_bpf_filter("vlan 20 and not arp")
        == "vlan 20 and not arp"
    )
    assert (
        normalize_bpf_filter("host 192.0.2.1 or ether proto 0x0800")
        == "host 192.0.2.1 or ether proto 0x0800"
    )
    assert (
        normalize_bpf_filter("src net 198.51.100.0/24 and (tcp or udp)")
        == "src net 198.51.100.0/24 and (tcp or udp)"
    )


def test_shell_and_quote_characters_are_rejected():
    for value in (
        "tcp; id",
        "$(reboot)",
        "`id`",
        'tcp port "80"',
        "tcp\nport 80",
        "tcp\x00port",
    ):
        try:
            normalize_bpf_filter(value)
        except BpfFilterError as exc:
            assert exc.code == "invalid_filter"
        else:
            raise AssertionError(f"expected rejection: {value!r}")


def test_ampersand_filter_is_argv_safe_tcpdump_syntax():
    assert normalize_bpf_filter("tcp && port 80") == "tcp && port 80"


def test_filter_length_and_parentheses_are_validated():
    try:
        normalize_bpf_filter("tcp " + ("port 80 " * 80))
    except BpfFilterError as exc:
        assert "at most" in exc.message
    else:
        raise AssertionError("oversized filter must fail")
    try:
        normalize_bpf_filter("tcp and (port 80")
    except BpfFilterError as exc:
        assert "parentheses" in exc.message
    else:
        raise AssertionError("unmatched parentheses must fail")
