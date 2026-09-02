from __future__ import annotations

from dataclasses import dataclass

from scapy.all import DNS, IP, rdpcap

# coduri numerice standard pentru tipurile de interogare DNS uzuale -
# doar cele relevante pentru heuristica de tunneling (TXT/NULL/CNAME sunt
# folosite frecvent pentru exfiltrare, pot transporta mai multe date
# decat un simplu A record)
_QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 10: "NULL"}


@dataclass
class DnsQuery:
    timestamp: float
    src_ip: str
    query_name: str
    query_type: str


def extract_dns_query(pkt) -> DnsQuery | None:
    """None daca pachetul nu e o INTEROGARE DNS (qr=0) - raspunsurile
    (qr=1) nu sunt relevante pentru heuristica de tunneling, care se
    uita la ce intreaba clientul, nu la ce raspunde serverul"""
    if DNS not in pkt or IP not in pkt:
        return None
    dns = pkt[DNS]
    if dns.qr != 0 or dns.qdcount == 0 or dns.qd is None:
        return None

    qname = dns.qd.qname
    if isinstance(qname, bytes):
        qname = qname.decode("utf-8", errors="replace")
    qname = qname.rstrip(".")

    return DnsQuery(
        timestamp=float(pkt.time),
        src_ip=pkt[IP].src,
        query_name=qname,
        query_type=_QTYPE_NAMES.get(int(dns.qd.qtype), str(dns.qd.qtype)),
    )


def read_pcap_dns_queries(path: str) -> list[DnsQuery]:
    packets = rdpcap(path)
    queries = (extract_dns_query(pkt) for pkt in packets)
    return [q for q in queries if q is not None]
