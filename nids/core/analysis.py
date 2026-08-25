from dataclasses import dataclass

from nids.capture.packet_meta import PacketMeta
from nids.capture.pcap_reader import read_pcap
from nids.core.event import Event, Severity
from nids.signatures.port_scan import DEFAULT_PORT_THRESHOLD, PortScanEvent, detect_port_scans
from nids.signatures.sensitive_ports import detect_sensitive_port_contacts, event_from_sensitive_port


def analyze_pcap(
    path: str,
    port_scan_threshold: int = DEFAULT_PORT_THRESHOLD,
    port_scan_window: float | None = None,
    sensitive_ports: set[int] | None = None,
) -> list[Event]:
    packets = read_pcap(path)
    events = [
        event_from_port_scan(scan)
        for scan in detect_port_scans(
            packets, threshold=port_scan_threshold, window_seconds=port_scan_window
        )
    ]
    events.extend(
        event_from_sensitive_port(evt)
        for evt in detect_sensitive_port_contacts(packets, sensitive_ports or set())
    )
    return events


def event_from_port_scan(scan: PortScanEvent, hits: int = 1) -> Event:
    ports_preview = ", ".join(str(p) for p in scan.ports[:10])
    if len(scan.ports) > 10:
        ports_preview += ", ..."
    suffix = f" - sesizat de {hits} ori" if hits > 1 else ""
    return Event(
        event_type="port scan",
        source_ip=scan.src_ip,
        severity=Severity.MEDIUM,
        description=(
            f"{scan.distinct_ports} porturi distincte contactate pe "
            f"{scan.dst_ip} ({ports_preview}){suffix}"
        ),
    )


@dataclass
class ScanUpdate:
    pair: tuple[str, str]
    event: Event
    is_new: bool


class StreamAnalyzer:
    """acumuleaza pachete dintr-un flux live si urmareste port scan-uri
    per (sursa, destinatie). primul prag depasit genereaza un eveniment
    nou; daca aceeasi sursa continua sa contacteze porturi noi dupa aceea,
    actualizeaza acelasi eveniment cu un contor in loc sa umple lista cu
    randuri identice. un port deja vazut nu conteaza a doua oara - doar
    porturi noi indica scanare in desfasurare, nu doar trafic normal"""

    def __init__(
        self, port_scan_threshold: int = DEFAULT_PORT_THRESHOLD, window_seconds: float | None = None
    ) -> None:
        self._threshold = port_scan_threshold
        self._window_seconds = window_seconds
        # port + timestamp-ul primului contact, nu doar port - necesar ca
        # sa putem elimina porturile iesite din fereastra cand exista una
        self._hits_by_pair: dict[tuple[str, str], list[tuple[int, float]]] = {}
        self._reported_hits_by_pair: dict[tuple[str, str], int] = {}

    def process_packet(self, pkt: PacketMeta) -> ScanUpdate | None:
        if pkt.dst_port is None:
            return None

        pair = (pkt.src_ip, pkt.dst_ip)
        hits = self._hits_by_pair.setdefault(pair, [])

        if self._window_seconds is not None:
            cutoff = pkt.timestamp - self._window_seconds
            hits[:] = [h for h in hits if h[1] >= cutoff]

        ports_before = {port for port, _ in hits}
        if pkt.dst_port in ports_before:
            return None

        was_flagged = len(ports_before) >= self._threshold
        hits.append((pkt.dst_port, pkt.timestamp))
        ports = {port for port, _ in hits}

        if len(ports) < self._threshold:
            return None

        self._reported_hits_by_pair[pair] = self._reported_hits_by_pair.get(pair, 0) + 1
        scan = PortScanEvent(
            src_ip=pair[0],
            dst_ip=pair[1],
            distinct_ports=len(ports),
            ports=sorted(ports),
        )
        event = event_from_port_scan(scan, hits=self._reported_hits_by_pair[pair])
        return ScanUpdate(pair=pair, event=event, is_new=not was_flagged)
