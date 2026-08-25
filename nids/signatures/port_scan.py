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
    packets: list[PacketMeta],
    threshold: int = DEFAULT_PORT_THRESHOLD,
    window_seconds: float | None = None,
) -> list[PortScanEvent]:
    """gasit prin numarul de porturi distincte contactate de aceeasi
    sursa catre aceeasi destinatie - fara filtrare pe flag-uri TCP
    (SYN) momentan, PacketMeta nu retine flags inca.

    window_seconds=None (implicit): comportamentul original, cumulativ pe
    tot fisierul/toata sesiunea - orice N porturi distincte, oricat de
    departate in timp, declanseaza evenimentul. cu o fereastra data, se
    cere ca cele N porturi sa fie atinse in interiorul unui interval de
    window_seconds - mai aproape de o scanare reala (rafala scurta), nu
    doar acumulare lenta de trafic normal peste o sesiune lunga"""
    hits_by_pair: dict[tuple[str, str], list[tuple[int, float]]] = defaultdict(list)

    for pkt in packets:
        if pkt.dst_port is None:
            continue
        hits_by_pair[(pkt.src_ip, pkt.dst_ip)].append((pkt.dst_port, pkt.timestamp))

    events = []
    for (src_ip, dst_ip), hits in hits_by_pair.items():
        if window_seconds is None:
            ports = sorted({port for port, _ in hits})
        else:
            ports = _ports_within_first_window_reaching_threshold(hits, threshold, window_seconds)
            if ports is None:
                continue

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


def _ports_within_first_window_reaching_threshold(
    hits: list[tuple[int, float]], threshold: int, window_seconds: float
) -> list[int] | None:
    """fereastra glisanta peste hit-urile unei singure perechi (sursa,
    destinatie), in ordine cronologica - intoarce porturile distincte din
    prima fereastra care atinge pragul, sau None daca niciuna nu-l atinge"""
    hits_sorted = sorted(hits, key=lambda h: h[1])
    window: list[tuple[int, float]] = []
    for port, timestamp in hits_sorted:
        window.append((port, timestamp))
        cutoff = timestamp - window_seconds
        window = [h for h in window if h[1] >= cutoff]
        distinct = {p for p, _ in window}
        if len(distinct) >= threshold:
            return sorted(distinct)
    return None
