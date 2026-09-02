from __future__ import annotations

from dataclasses import dataclass

from scapy.all import ARP, rdpcap


@dataclass
class ArpFrame:
    """spre deosebire de PacketMeta (strict IP), ARP e un protocol
    separat, la nivel de retea locala - nu are IP sursa/destinatie in
    sensul obisnuit, ci o legatura IP<->MAC afirmata de expeditor"""

    timestamp: float
    sender_ip: str
    sender_mac: str
    target_ip: str
    is_reply: bool  # opcode 2 = reply, 1 = request


def extract_arp_frame(pkt) -> ArpFrame:
    arp = pkt[ARP]
    return ArpFrame(
        timestamp=float(pkt.time),
        sender_ip=arp.psrc,
        sender_mac=arp.hwsrc,
        target_ip=arp.pdst,
        is_reply=arp.op == 2,
    )


def read_pcap_arp(path: str) -> list[ArpFrame]:
    """analog cu pcap_reader.read_pcap(), dar pentru cadre ARP - fisierul
    e citit separat (nu impartit cu read_pcap), la fel ca restul
    modulelor de analiza care recitesc PCAP-ul de fiecare data"""
    packets = rdpcap(path)
    return [extract_arp_frame(pkt) for pkt in packets if ARP in pkt]
