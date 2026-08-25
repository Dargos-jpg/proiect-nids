from nids.capture.packet_meta import PacketMeta
from nids.signatures.sensitive_ports import (
    SensitivePortTracker,
    detect_sensitive_port_contacts,
    event_from_sensitive_port,
)


def _packet(dst_port: int, src_ip: str = "10.0.0.1", dst_ip: str = "10.0.0.2") -> PacketMeta:
    return PacketMeta(
        timestamp=0.0,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol="tcp",
        length=60,
        src_port=40000,
        dst_port=dst_port,
    )


def test_detects_contact_to_sensitive_port():
    packets = [_packet(22)]

    events = detect_sensitive_port_contacts(packets, {22, 3389})

    assert len(events) == 1
    assert events[0].port == 22
    assert events[0].src_ip == "10.0.0.1"


def test_ignores_non_sensitive_ports():
    packets = [_packet(80), _packet(443)]

    events = detect_sensitive_port_contacts(packets, {22, 3389})

    assert events == []


def test_deduplicates_repeated_contact_same_pair_and_port():
    packets = [_packet(22), _packet(22), _packet(22)]

    events = detect_sensitive_port_contacts(packets, {22})

    assert len(events) == 1


def test_reports_separately_for_different_ports():
    packets = [_packet(22), _packet(3389)]

    events = detect_sensitive_port_contacts(packets, {22, 3389})

    assert {e.port for e in events} == {22, 3389}


def test_empty_sensitive_ports_list_disables_detection():
    packets = [_packet(22), _packet(3389)]

    events = detect_sensitive_port_contacts(packets, set())

    assert events == []


def test_single_contact_below_port_scan_threshold_still_flagged():
    """chiar un singur contact catre un port sensibil trebuie semnalat -
    nu are nevoie sa atinga niciun prag de numar de porturi, spre
    deosebire de semnatura de port scan"""
    events = detect_sensitive_port_contacts([_packet(22)], {22})

    assert len(events) == 1


def test_event_from_sensitive_port_carries_connection_identity():
    events = detect_sensitive_port_contacts([_packet(22)], {22})

    event = event_from_sensitive_port(events[0])

    assert event.source_ip == "10.0.0.1"
    assert event.dest_ip == "10.0.0.2"
    assert event.dest_port == 22
    assert "22" in event.description


def test_tracker_flags_first_contact_and_ignores_repeats():
    tracker = SensitivePortTracker({22})

    first = tracker.process_packet(_packet(22))
    second = tracker.process_packet(_packet(22))

    assert first is not None
    assert second is None


def test_tracker_ignores_non_sensitive_ports():
    tracker = SensitivePortTracker({22})

    assert tracker.process_packet(_packet(80)) is None


def test_tracker_treats_different_ips_independently():
    tracker = SensitivePortTracker({22})

    first = tracker.process_packet(_packet(22, src_ip="10.0.0.1"))
    second = tracker.process_packet(_packet(22, src_ip="10.0.0.9"))

    assert first is not None
    assert second is not None
