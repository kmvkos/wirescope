from datetime import datetime, timezone

from engine.assessment import build_assessment, infer_ipv4_groups
from engine.passive_models import (
    CaptureResult,
    CaptureStatus,
    ConfidenceLevel,
    SensorResult,
    SensorStatus,
)
from tests.helpers import tool_result


def capture(frames):
    now = datetime.now(timezone.utc)
    return CaptureResult(
        interface="fixture",
        status=CaptureStatus.COMPLETED,
        started_at=now,
        finished_at=now,
        duration_seconds=1,
        frame_count=frames,
        retained=True,
        tool_result=tool_result(),
    )


def sensor(name, *, status="absent", hits=0, summary=None):
    return SensorResult(
        name=name,
        status=SensorStatus(status),
        hits=hits,
        summary=summary or {},
    )


def test_arp_groups_are_explicit_hints_not_subnets():
    groups = infer_ipv4_groups(
        [
            {"ipv4": "10.20.30.1"},
            {"ipv4": "10.20.30.15"},
            {"ipv4": "10.20.40.1"},
        ]
    )

    assert groups[0].value == {
        "candidate_group": "10.20.30.0/24",
        "hosts_observed": 2,
    }
    assert groups[0].confidence == ConfidenceLevel.HINT
    assert "actual subnet mask" in groups[0].limitations[0]


def test_untagged_traffic_is_not_claimed_as_no_vlan():
    assessment = build_assessment(
        capture(20),
        {
            "ethernet": sensor(
                "ethernet",
                status="detected",
                hits=20,
            ),
            "vlan": sensor("vlan"),
        },
    )

    hint = assessment.layer2["port_type_hint"]
    assert hint["value"] == "access-or-native-like"
    assert hint["confidence"] == ConfidenceLevel.HINT.value
    assert any(
        "does not prove" in limitation
        for limitation in hint["limitations"]
    )


def test_multiple_tagged_vlans_produce_medium_trunk_hint():
    assessment = build_assessment(
        capture(20),
        {
            "ethernet": sensor(
                "ethernet",
                status="detected",
                hits=20,
            ),
            "vlan": sensor(
                "vlan",
                status="detected",
                hits=4,
                summary={
                    "tagged_frames": 4,
                    "vlan_frame_counts": [
                        {"vlan_id": 10, "frames": 2},
                        {"vlan_id": 20, "frames": 2},
                    ],
                },
            ),
        },
    )

    hint = assessment.layer2["port_type_hint"]
    assert hint["value"] == "trunk-like"
    assert hint["confidence"] == ConfidenceLevel.MEDIUM.value


def test_stp_root_is_copied_into_layer2_assessment():
    assessment = build_assessment(
        capture(4),
        {
            "stp": SensorResult(
                name="stp",
                status=SensorStatus.DETECTED,
                hits=2,
                summary={
                    "bpdus_observed": 2,
                    "root_bridge_ids": ["32768.02:00:00:00:00:01"],
                    "bridge_ids": ["32768.02:00:00:00:00:02"],
                },
            )
        },
    )
    assert assessment.layer2["stp"]["bpdus_observed"] == 2
    assert assessment.layer2["stp"]["root_bridge_ids"] == [
        "32768.02:00:00:00:00:01"
    ]


def test_visibility_confidence_handles_silent_and_quiet_capture():
    silent = build_assessment(capture(0), {})
    quiet = build_assessment(capture(3), {})

    assert silent.visibility.value == "silent"
    assert silent.visibility.confidence == ConfidenceLevel.HIGH
    assert quiet.visibility.value == "very-low"
    assert quiet.visibility.confidence == ConfidenceLevel.HIGH
