from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from nids.capture.pcap_reader import PacketMeta
from nids.core.event import Event, Severity

DEFAULT_ATTEMPT_THRESHOLD = 5
DEFAULT_WINDOW_SECONDS = 30.0

# servicii tinta comune pentru brute-force (autentificare) - editabila din UI
DEFAULT_BRUTE_FORCE_PORTS: set[int] = {21, 22, 23, 3389}


@dataclass
class BruteForceEvent:
    src_ip: str
    dst_ip: str
    dst_port: int
    attempts: int


def event_from_brute_force(scan: BruteForceEvent) -> Event:
    return Event(
        event_type="brute-force",
        source_ip=scan.src_ip,
        severity=Severity.HIGH,
        description=(
            f"{scan.attempts} incercari de conectare catre serviciul de pe "
            f"portul {scan.dst_port} pe {scan.dst_ip}, intr-un interval scurt"
        ),
        dest_ip=scan.dst_ip,
        dest_port=scan.dst_port,
    )


def detect_brute_force(
    packets: list[PacketMeta],
    threshold: int = DEFAULT_ATTEMPT_THRESHOLD,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    target_ports: set[int] | None = None,
) -> list[BruteForceEvent]:
    """brute-force = multe incercari de conectare catre ACELASI serviciu
    (un singur port), de la aceeasi sursa, intr-o fereastra scurta - spre
    deosebire de port scan, care numara porturi DISTINCTE. o "incercare"
    e aproximata printr-un src_port distinct (fiecare conexiune noua TCP
    porneste tipic de pe un port efemer nou) - nu avem parsare a
    continutului de autentificare (username/parola), doar volumul de
    conexiuni catre acel serviciu"""
    target_ports = target_ports if target_ports is not None else DEFAULT_BRUTE_FORCE_PORTS
    hits_by_target: dict[tuple[str, str, int], list[tuple[int, float]]] = defaultdict(list)

    for pkt in packets:
        if pkt.dst_port not in target_ports or pkt.src_port is None:
            continue
        hits_by_target[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)].append(
            (pkt.src_port, pkt.timestamp)
        )

    events = []
    for (src_ip, dst_ip, dst_port), hits in hits_by_target.items():
        attempts = _attempts_within_first_window_reaching_threshold(hits, threshold, window_seconds)
        if attempts is not None:
            events.append(
                BruteForceEvent(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, attempts=attempts)
            )
    return events


def _attempts_within_first_window_reaching_threshold(
    hits: list[tuple[int, float]], threshold: int, window_seconds: float
) -> int | None:
    """fereastra glisanta peste hit-urile (src_port, timestamp) ale unei
    singure tinte, in ordine cronologica - intoarce numarul de src_port-uri
    distincte din prima fereastra care atinge pragul, sau None daca
    niciuna nu-l atinge. acelasi tipar ca port_scan.py, doar numarand
    porturi SURSA distincte (incercari), nu porturi DESTINATIE distincte"""
    hits_sorted = sorted(hits, key=lambda h: h[1])
    window: list[tuple[int, float]] = []
    for src_port, timestamp in hits_sorted:
        window.append((src_port, timestamp))
        cutoff = timestamp - window_seconds
        window = [h for h in window if h[1] >= cutoff]
        distinct = {p for p, _ in window}
        if len(distinct) >= threshold:
            return len(distinct)
    return None


class BruteForceTracker:
    """varianta live (streaming) - la fel ca StreamAnalyzer pentru port
    scan, dar numara src_port-uri distincte catre ACELASI (dst_ip,
    dst_port), nu dst_port-uri distincte. raporteaza o singura data per
    (sursa, destinatie, port) cat timp fereastra ramane peste prag -
    actualizeaza contorul in loc sa umple lista cu randuri identice"""

    def __init__(
        self,
        threshold: int = DEFAULT_ATTEMPT_THRESHOLD,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        target_ports: set[int] | None = None,
    ) -> None:
        self._threshold = threshold
        self._window_seconds = window_seconds
        self._target_ports = target_ports if target_ports is not None else DEFAULT_BRUTE_FORCE_PORTS
        self._hits_by_target: dict[tuple[str, str, int], list[tuple[int, float]]] = {}
        self._reported: set[tuple[str, str, int]] = set()

    def process_packet(self, pkt: PacketMeta) -> Event | None:
        if pkt.dst_port not in self._target_ports or pkt.src_port is None:
            return None

        key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port)
        hits = self._hits_by_target.setdefault(key, [])

        cutoff = pkt.timestamp - self._window_seconds
        hits[:] = [h for h in hits if h[1] >= cutoff]

        if pkt.src_port not in {p for p, _ in hits}:
            hits.append((pkt.src_port, pkt.timestamp))

        distinct = len({p for p, _ in hits})
        if distinct < self._threshold:
            return None
        if key in self._reported:
            return None

        self._reported.add(key)
        return event_from_brute_force(
            BruteForceEvent(src_ip=pkt.src_ip, dst_ip=pkt.dst_ip, dst_port=pkt.dst_port, attempts=distinct)
        )
