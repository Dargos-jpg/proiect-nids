from scapy.all import ICMP, IP, TCP, UDP, Raw

from nids.capture.packet_meta import extract_meta


def _build(pkt):
    """round-trip prin bytes, ca la testele DNS - unele campuri (ex.
    lungimi calculate) nu sunt populate corect decat dupa serializare"""
    return IP(bytes(pkt))


def test_tcp_packet_extracts_window_size():
    pkt = _build(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, window=64240))

    meta = extract_meta(pkt)

    assert meta.tcp_window == 64240
    assert meta.protocol == "tcp"


def test_udp_packet_has_no_tcp_window():
    pkt = _build(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=53))

    meta = extract_meta(pkt)

    assert meta.tcp_window is None
    assert meta.protocol == "udp"


def test_icmp_packet_has_no_tcp_window():
    pkt = _build(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())

    meta = extract_meta(pkt)

    assert meta.tcp_window is None
    assert meta.protocol == "icmp"


def test_packet_without_payload_has_zero_payload_length():
    pkt = _build(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80))

    meta = extract_meta(pkt)

    assert meta.payload_length == 0


def test_packet_with_payload_reports_its_length():
    pkt = _build(
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80) / Raw(load=b"hello world")
    )

    meta = extract_meta(pkt)

    assert meta.payload_length == len(b"hello world")
