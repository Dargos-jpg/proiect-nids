from __future__ import annotations

from dataclasses import dataclass

from scapy.all import IP, TCP, UDP, Raw, rdpcap


@dataclass
class PayloadSample:
    src_ip: str
    dst_ip: str
    dst_port: int | None
    payload: bytes


def extract_payload_sample(pkt) -> PayloadSample | None:
    """None daca pachetul nu are date de aplicatie (doar SYN/ACK gol,
    de exemplu) - Raw e stratul scapy pentru octetii ramasi neinterpretati
    de niciun protocol cunoscut, adica exact payload-ul de aplicatie"""
    if Raw not in pkt or IP not in pkt:
        return None
    payload = bytes(pkt[Raw].load)
    if not payload:
        return None

    dst_port: int | None = None
    if TCP in pkt:
        dst_port = int(pkt[TCP].dport)
    elif UDP in pkt:
        dst_port = int(pkt[UDP].dport)

    return PayloadSample(
        src_ip=pkt[IP].src, dst_ip=pkt[IP].dst, dst_port=dst_port, payload=payload
    )


def read_pcap_payload_samples(path: str) -> list[PayloadSample]:
    packets = rdpcap(path)
    samples = (extract_payload_sample(pkt) for pkt in packets)
    return [s for s in samples if s is not None]
