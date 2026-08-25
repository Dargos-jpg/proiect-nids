from pathlib import Path

from nids.capture.pcap_reader import PacketMeta, read_pcap
from nids.signatures.port_scan import detect_port_scans

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"


def _packet(dst_port: int, timestamp: float = 0.0) -> PacketMeta:
    return PacketMeta(
        timestamp=timestamp,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol="tcp",
        length=60,
        src_port=40000,
        dst_port=dst_port,
    )


def test_normal_traffic_has_no_port_scan():
    packets = read_pcap(str(PCAP_PATH))

    events = detect_port_scans(packets)

    assert events == []


def test_many_distinct_ports_triggers_port_scan():
    packets = [_packet(port) for port in range(20, 26)]

    events = detect_port_scans(packets, threshold=5)

    assert len(events) == 1
    event = events[0]
    assert event.src_ip == "10.0.0.1"
    assert event.dst_ip == "10.0.0.2"
    assert event.distinct_ports == 6


def test_few_distinct_ports_does_not_trigger():
    packets = [_packet(port) for port in range(20, 23)]

    events = detect_port_scans(packets, threshold=5)

    assert events == []


def test_window_ignores_older_events_outside_window():
    """5 porturi in 60s (in afara ferestrei de 10s), niciodata mai putin
    de 10s intre ele - nu ar trebui sa declanseze cu o fereastra de 10s"""
    packets = [_packet(port, timestamp=i * 15.0) for i, port in enumerate(range(20, 25))]

    events = detect_port_scans(packets, threshold=5, window_seconds=10.0)

    assert events == []


def test_window_triggers_when_ports_clustered_in_time():
    packets = [_packet(port, timestamp=i * 1.0) for i, port in enumerate(range(20, 25))]

    events = detect_port_scans(packets, threshold=5, window_seconds=10.0)

    assert len(events) == 1
    assert events[0].distinct_ports == 5


def test_window_none_preserves_unbounded_behavior():
    packets = [_packet(port, timestamp=i * 1000.0) for i, port in enumerate(range(20, 25))]

    events = detect_port_scans(packets, threshold=5, window_seconds=None)

    assert len(events) == 1
