from nids.capture.packet_meta import PacketMeta
from nids.core.event import Severity
from nids.signatures.brute_force import (
    BruteForceEvent,
    detect_brute_force,
    event_from_brute_force,
)


def _packet(src_port: int, dst_port: int = 22, timestamp: float = 0.0) -> PacketMeta:
    return PacketMeta(
        timestamp=timestamp,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol="tcp",
        length=60,
        src_port=src_port,
        dst_port=dst_port,
    )


def test_many_attempts_within_window_triggers_event():
    packets = [_packet(src_port=p, timestamp=i * 1.0) for i, p in enumerate(range(40000, 40005))]

    events = detect_brute_force(packets, threshold=5, window_seconds=30.0)

    assert len(events) == 1
    assert events[0].src_ip == "10.0.0.1"
    assert events[0].dst_ip == "10.0.0.2"
    assert events[0].dst_port == 22
    assert events[0].attempts == 5


def test_few_attempts_does_not_trigger():
    packets = [_packet(src_port=p) for p in range(40000, 40003)]

    events = detect_brute_force(packets, threshold=5, window_seconds=30.0)

    assert events == []


def test_ignores_non_target_ports():
    packets = [_packet(src_port=p, dst_port=80) for p in range(40000, 40010)]

    events = detect_brute_force(packets, threshold=5, window_seconds=30.0, target_ports={22})

    assert events == []


def test_attempts_spread_outside_window_do_not_trigger():
    packets = [_packet(src_port=p, timestamp=i * 60.0) for i, p in enumerate(range(40000, 40005))]

    events = detect_brute_force(packets, threshold=5, window_seconds=10.0)

    assert events == []


def test_repeated_same_source_port_counts_once():
    packets = [_packet(src_port=40000, timestamp=i * 1.0) for i in range(10)]

    events = detect_brute_force(packets, threshold=5, window_seconds=30.0)

    assert events == []  # un singur src_port distinct, oricate pachete


def test_custom_target_ports():
    packets = [_packet(src_port=p, dst_port=3389) for p in range(40000, 40006)]

    events = detect_brute_force(packets, threshold=5, window_seconds=30.0, target_ports={3389})

    assert len(events) == 1
    assert events[0].dst_port == 3389


def test_event_from_brute_force_has_high_severity():
    scan = BruteForceEvent(src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=22, attempts=7)

    event = event_from_brute_force(scan)

    assert event.severity == Severity.HIGH
    assert event.source_ip == "10.0.0.1"
    assert event.dest_ip == "10.0.0.2"
    assert event.dest_port == 22
    assert "7" in event.description
