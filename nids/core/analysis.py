from dataclasses import dataclass

from nids.capture.arp_meta import read_pcap_arp
from nids.capture.dns_meta import read_pcap_dns_queries
from nids.capture.packet_meta import PacketMeta
from nids.capture.pcap_reader import read_pcap
from nids.capture.payload_meta import read_pcap_payload_samples
from nids.core.event import Event, Severity
from nids.signatures.arp_spoofing import detect_arp_spoofing, event_from_arp_spoof
from nids.signatures.brute_force import (
    DEFAULT_ATTEMPT_THRESHOLD,
    DEFAULT_WINDOW_SECONDS as DEFAULT_BRUTE_FORCE_WINDOW_SECONDS,
    detect_brute_force,
    event_from_brute_force,
)
from nids.signatures.dns_tunneling import (
    DEFAULT_MIN_ENTROPY,
    DEFAULT_MIN_LABEL_LENGTH,
    detect_dns_tunneling,
    event_from_dns_tunnel,
)
from nids.signatures.payload_signatures import detect_payload_signatures, event_from_payload_match
from nids.signatures.port_scan import DEFAULT_PORT_THRESHOLD, PortScanEvent, detect_port_scans
from nids.signatures.sensitive_ports import detect_sensitive_port_contacts, event_from_sensitive_port


def analyze_pcap(
    path: str,
    port_scan_threshold: int = DEFAULT_PORT_THRESHOLD,
    port_scan_window: float | None = None,
    sensitive_ports: set[int] | None = None,
    brute_force_threshold: int = DEFAULT_ATTEMPT_THRESHOLD,
    brute_force_window: float = DEFAULT_BRUTE_FORCE_WINDOW_SECONDS,
    brute_force_ports: set[int] | None = None,
    dns_min_label_length: int = DEFAULT_MIN_LABEL_LENGTH,
    dns_min_entropy: float = DEFAULT_MIN_ENTROPY,
    payload_signatures_enabled: bool = True,
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
    events.extend(
        event_from_brute_force(evt)
        for evt in detect_brute_force(
            packets,
            threshold=brute_force_threshold,
            window_seconds=brute_force_window,
            target_ports=brute_force_ports,
        )
    )
    events.extend(
        event_from_arp_spoof(evt) for evt in detect_arp_spoofing(read_pcap_arp(path))
    )
    events.extend(
        event_from_dns_tunnel(evt)
        for evt in detect_dns_tunneling(
            read_pcap_dns_queries(path),
            min_label_length=dns_min_label_length,
            min_entropy=dns_min_entropy,
        )
    )
    if payload_signatures_enabled:
        events.extend(
            event_from_payload_match(m)
            for m in detect_payload_signatures(read_pcap_payload_samples(path))
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
