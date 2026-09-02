from nids.capture.packet_meta import PacketMeta
from nids.signatures.brute_force import BruteForceTracker


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


def test_emits_event_once_threshold_crossed():
    tracker = BruteForceTracker(threshold=3, window_seconds=30.0)

    events = [
        tracker.process_packet(_packet(src_port=p, timestamp=i * 1.0))
        for i, p in enumerate(range(40000, 40003))
    ]

    assert events[0] is None
    assert events[1] is None
    assert events[2] is not None
    assert events[2].source_ip == "10.0.0.1"


def test_does_not_report_same_target_twice():
    tracker = BruteForceTracker(threshold=3, window_seconds=30.0)
    for i, p in enumerate(range(40000, 40003)):
        tracker.process_packet(_packet(src_port=p, timestamp=i * 1.0))

    event = tracker.process_packet(_packet(src_port=40003, timestamp=3.0))

    assert event is None


def test_ignores_non_target_ports():
    tracker = BruteForceTracker(threshold=2, window_seconds=30.0, target_ports={22})

    event = tracker.process_packet(_packet(src_port=40000, dst_port=80))

    assert event is None


def test_ignores_repeat_of_already_seen_source_port():
    tracker = BruteForceTracker(threshold=3, window_seconds=30.0)
    tracker.process_packet(_packet(src_port=40000, timestamp=0.0))

    event = tracker.process_packet(_packet(src_port=40000, timestamp=1.0))

    assert event is None


def test_window_ignores_attempts_that_aged_out():
    tracker = BruteForceTracker(threshold=3, window_seconds=10.0)

    tracker.process_packet(_packet(src_port=40000, timestamp=0.0))
    tracker.process_packet(_packet(src_port=40001, timestamp=5.0))
    event = tracker.process_packet(_packet(src_port=40002, timestamp=25.0))  # primul a iesit din fereastra

    assert event is None
