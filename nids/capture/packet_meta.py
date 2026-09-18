from __future__ import annotations

from dataclasses import dataclass

from scapy.all import ICMP, IP, TCP, UDP, Raw


@dataclass
class PacketMeta:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    is_fragmented: bool = False
    # doua campuri noi, cu default ca sa nu strice apelurile/testele
    # existente - folosite doar de nids/ml/features/cicflow_style.py
    # (schema de features pentru al doilea model expert, CSE-CIC-IDS2018):
    # dimensiunea ferestrei TCP (doar pe pachetul SYN/SYN-ACK e relevanta -
    # "Init Fwd/Bwd Win Byts") si lungimea payload-ului aplicatie (fara sa
    # stocam octetii - doar cati sunt, pentru "Fwd Act Data Pkts")
    tcp_window: int | None = None
    payload_length: int = 0


def extract_meta(pkt) -> PacketMeta:
    ip_layer = pkt[IP]
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    tcp_window: int | None = None

    if TCP in pkt:
        protocol = "tcp"
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
        tcp_flags = str(pkt[TCP].flags)
        tcp_window = int(pkt[TCP].window)
    elif UDP in pkt:
        protocol = "udp"
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)
    elif ICMP in pkt:
        protocol = "icmp"
    else:
        protocol = str(ip_layer.proto)

    is_fragmented = int(ip_layer.frag) != 0 or "MF" in str(ip_layer.flags)
    payload_length = len(pkt[Raw].load) if Raw in pkt else 0

    return PacketMeta(
        timestamp=float(pkt.time),
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        protocol=protocol,
        length=len(pkt),
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        is_fragmented=is_fragmented,
        tcp_window=tcp_window,
        payload_length=payload_length,
    )
