from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from nids.capture.pcap_reader import PacketMeta

DEFAULT_PORT_THRESHOLD = 5


@dataclass
class PortScanEvent:
    src_ip: str
    dst_ip: str
    distinct_ports: int
    ports: list[int]


def detect_port_scans(
    packets: list[PacketMeta], threshold: int = DEFAULT_PORT_THRESHOLD
) -> list[PortScanEvent]:
    """gasit prin numarul de porturi distincte contactate de aceeasi
    sursa catre aceeasi destinatie - fara filtrare pe flag-uri TCP
    (SYN) momentan, PacketMeta nu retine flags inca"""
    ports_by_pair: dict[tuple[str, str], set[int]] = defaultdict(set)

    for pkt in packets:
        if pkt.dst_port is None:
            continue
        ports_by_pair[(pkt.src_ip, pkt.dst_ip)].add(pkt.dst_port)

    events = []
    for (src_ip, dst_ip), ports in ports_by_pair.items():
        if len(ports) >= threshold:
            events.append(
                PortScanEvent(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    distinct_ports=len(ports),
                    ports=sorted(ports),
                )
            )
    return events
