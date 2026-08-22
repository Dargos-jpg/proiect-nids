from pathlib import Path

from nids.capture.pcap_reader import PacketMeta, read_pcap
from nids.signatures.port_scan import detect_port_scans

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"


def _packet(dst_port: int) -> PacketMeta:
    return PacketMeta(
        timestamp=0.0,
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
