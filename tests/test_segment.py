from engine.segment import had_l3_address, segment_note, segment_status


def test_link_local_and_empty_addresses_are_not_usable_l3():
    assert had_l3_address([], []) is False
    assert had_l3_address([], ["fe80::1/64"]) is False
    assert had_l3_address(["127.0.0.1/8"], []) is False
    assert had_l3_address(["192.0.2.10/24"], []) is True
    assert had_l3_address([], ["2001:db8::10/64"]) is True


def test_segment_status_does_not_invent_vlans_for_untagged_traffic():
    assert segment_status(
        frame_count=0,
        tagged_vlan_ids=[],
        untagged_traffic_observed=False,
    ) == "quiet"
    assert segment_status(
        frame_count=12,
        tagged_vlan_ids=[10, 20],
        untagged_traffic_observed=True,
    ) == "tagged_vlans"
    assert segment_status(
        frame_count=12,
        tagged_vlan_ids=[],
        untagged_traffic_observed=True,
    ) == "untagged_traffic"
    assert "VLAN ID is unknown" in segment_note(
        status="untagged_traffic",
        tagged_vlan_ids=[],
        frame_count=12,
    )
    assert "10, 20" in segment_note(
        status="tagged_vlans",
        tagged_vlan_ids=[10, 20],
        frame_count=12,
    )
