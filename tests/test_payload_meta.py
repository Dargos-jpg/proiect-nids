from scapy.all import IP, TCP, UDP, Raw

from nids.capture.payload_meta import extract_payload_sample


def _tcp_packet(src_ip: str, dst_ip: str, dst_port: int, payload: bytes):
    return IP(src=src_ip, dst=dst_ip) / TCP(sport=5000, dport=dst_port) / Raw(load=payload)


def test_extract_payload_sample_reads_identity_and_bytes():
    pkt = _tcp_packet("10.0.0.5", "10.0.0.9", 80, b"GET / HTTP/1.1")

    sample = extract_payload_sample(pkt)

    assert sample is not None
    assert sample.src_ip == "10.0.0.5"
    assert sample.dst_ip == "10.0.0.9"
    assert sample.dst_port == 80
    assert sample.payload == b"GET / HTTP/1.1"


def test_extract_payload_sample_reads_udp_port():
    pkt = IP(src="10.0.0.5", dst="10.0.0.9") / UDP(sport=5000, dport=53) / Raw(load=b"data")

    sample = extract_payload_sample(pkt)

    assert sample.dst_port == 53


def test_extract_payload_sample_returns_none_without_payload():
    pkt = IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=5000, dport=80)

    assert extract_payload_sample(pkt) is None


def test_extract_payload_sample_returns_none_without_ip():
    pkt = TCP(sport=5000, dport=80) / Raw(load=b"data")

    assert extract_payload_sample(pkt) is None
