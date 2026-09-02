from scapy.all import DNS, IP, UDP, DNSQR

from nids.capture.dns_meta import extract_dns_query


def _dns_packet(qname: str, src_ip: str = "10.0.0.5", qr: int = 0, qtype: str = "A"):
    """round-trip prin bytes() - un pachet construit direct in memorie nu
    are qdcount calculat (ramane None) pana e serializat, spre deosebire
    de un pachet real sniffat de pe retea. reparsarea imita corect ce
    vede captura live"""
    pkt = (
        IP(src=src_ip, dst="8.8.8.8")
        / UDP(sport=5000, dport=53)
        / DNS(qr=qr, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    )
    return IP(bytes(pkt))


def test_extract_dns_query_reads_name_and_source():
    pkt = _dns_packet("www.example.com")

    query = extract_dns_query(pkt)

    assert query is not None
    assert query.src_ip == "10.0.0.5"
    assert query.query_name == "www.example.com"
    assert query.query_type == "A"


def test_extract_dns_query_returns_none_for_responses():
    pkt = _dns_packet("www.example.com", qr=1)

    assert extract_dns_query(pkt) is None


def test_extract_dns_query_reads_txt_type():
    pkt = _dns_packet("www.example.com", qtype="TXT")

    query = extract_dns_query(pkt)

    assert query.query_type == "TXT"


def test_extract_dns_query_returns_none_for_non_dns_packets():
    pkt = IP(src="10.0.0.5", dst="10.0.0.2") / UDP(sport=1234, dport=80)

    assert extract_dns_query(pkt) is None
