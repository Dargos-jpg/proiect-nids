from __future__ import annotations

from scapy.all import IP, rdpcap

from nids.capture.packet_meta import PacketMeta, extract_meta

__all__ = ["PacketMeta", "read_pcap"]


def read_pcap(path: str) -> list[PacketMeta]:
    packets = rdpcap(path)
    return [extract_meta(pkt) for pkt in packets if IP in pkt]
