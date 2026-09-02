from nids.capture.arp_meta import ArpFrame
from nids.core.event import Severity
from nids.signatures.arp_spoofing import (
    ArpSpoofEvent,
    ArpSpoofTracker,
    detect_arp_spoofing,
    event_from_arp_spoof,
)


def _frame(sender_ip: str, sender_mac: str, timestamp: float = 0.0) -> ArpFrame:
    return ArpFrame(
        timestamp=timestamp, sender_ip=sender_ip, sender_mac=sender_mac, target_ip="10.0.0.1", is_reply=True
    )


def test_no_events_when_mac_stays_consistent():
    frames = [_frame("10.0.0.5", "aa:aa", timestamp=i) for i in range(5)]

    events = detect_arp_spoofing(frames)

    assert events == []


def test_flags_mac_change_for_same_ip():
    frames = [
        _frame("10.0.0.5", "aa:aa", timestamp=0.0),
        _frame("10.0.0.5", "bb:bb", timestamp=1.0),
    ]

    events = detect_arp_spoofing(frames)

    assert len(events) == 1
    assert events[0].ip == "10.0.0.5"
    assert events[0].original_mac == "aa:aa"
    assert events[0].new_mac == "bb:bb"


def test_first_seen_binding_is_trusted_without_history():
    frames = [_frame("10.0.0.5", "aa:aa", timestamp=0.0)]

    events = detect_arp_spoofing(frames)

    assert events == []


def test_different_ips_do_not_interfere():
    frames = [
        _frame("10.0.0.5", "aa:aa", timestamp=0.0),
        _frame("10.0.0.6", "bb:bb", timestamp=1.0),
    ]

    events = detect_arp_spoofing(frames)

    assert events == []


def test_repeated_same_conflicting_mac_reported_once():
    frames = [
        _frame("10.0.0.5", "aa:aa", timestamp=0.0),
        _frame("10.0.0.5", "bb:bb", timestamp=1.0),
        _frame("10.0.0.5", "bb:bb", timestamp=2.0),
    ]

    events = detect_arp_spoofing(frames)

    assert len(events) == 1


def test_processes_frames_in_chronological_order_regardless_of_input_order():
    frames = [
        _frame("10.0.0.5", "bb:bb", timestamp=5.0),
        _frame("10.0.0.5", "aa:aa", timestamp=0.0),
    ]

    events = detect_arp_spoofing(frames)

    assert len(events) == 1
    assert events[0].original_mac == "aa:aa"
    assert events[0].new_mac == "bb:bb"


def test_event_from_arp_spoof_has_high_severity():
    evt = ArpSpoofEvent(ip="10.0.0.5", original_mac="aa:aa", new_mac="bb:bb")

    event = event_from_arp_spoof(evt)

    assert event.severity == Severity.HIGH
    assert event.source_ip == "10.0.0.5"
    assert "aa:aa" in event.description
    assert "bb:bb" in event.description


def test_tracker_emits_event_on_mac_change():
    tracker = ArpSpoofTracker()
    first = tracker.process_frame(_frame("10.0.0.5", "aa:aa"))
    second = tracker.process_frame(_frame("10.0.0.5", "bb:bb"))

    assert first is None
    assert second is not None
    assert second.source_ip == "10.0.0.5"


def test_tracker_does_not_report_same_conflict_twice():
    tracker = ArpSpoofTracker()
    tracker.process_frame(_frame("10.0.0.5", "aa:aa"))
    tracker.process_frame(_frame("10.0.0.5", "bb:bb"))

    event = tracker.process_frame(_frame("10.0.0.5", "bb:bb"))

    assert event is None


def test_tracker_reports_again_on_a_new_third_mac():
    tracker = ArpSpoofTracker()
    tracker.process_frame(_frame("10.0.0.5", "aa:aa"))
    tracker.process_frame(_frame("10.0.0.5", "bb:bb"))

    event = tracker.process_frame(_frame("10.0.0.5", "cc:cc"))

    assert event is not None
    assert event.description.count("bb:bb") >= 1
