from __future__ import annotations

from dataclasses import dataclass

from nids.capture.payload_meta import PayloadSample
from nids.core.event import Event, Severity

# set mic si curatat manual de pattern-uri cunoscute, nu un motor de reguli
# complet (stil Snort/Suricata) - suficient sa demonstreze tehnica, nu
# sa inlocuiasca un IDS de productie. EICAR e semnatura STANDARD de test
# antivirus (fisier inofensiv, folosit universal ca sa testezi ca un
# scanner de securitate chiar functioneaza), restul sunt pattern-uri
# text simple si larg cunoscute (traversare de director, SQLi, XSS,
# webshell) - nu bytecode de exploit real
@dataclass
class PayloadSignature:
    name: str
    pattern: bytes


DEFAULT_PAYLOAD_SIGNATURES: list[PayloadSignature] = [
    PayloadSignature("EICAR (test antivirus standard)", b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"),
    PayloadSignature("traversare director (Unix)", b"../../../etc/passwd"),
    PayloadSignature("traversare director (Windows)", b"..\\..\\..\\windows\\system32"),
    PayloadSignature("SQL injection (UNION SELECT)", b"UNION SELECT"),
    PayloadSignature("SQL injection (tautologie clasica)", b"' OR '1'='1"),
    PayloadSignature("XSS (tag script)", b"<script>"),
    PayloadSignature("posibil webshell (eval+base64)", b"eval(base64_decode("),
]


@dataclass
class PayloadMatch:
    src_ip: str
    dst_ip: str
    dst_port: int | None
    signature_name: str


def event_from_payload_match(match: PayloadMatch) -> Event:
    return Event(
        event_type="semnatura malware in payload",
        source_ip=match.src_ip,
        severity=Severity.HIGH,
        description=(
            f"payload-ul unei conexiuni catre {match.dst_ip} contine un pattern "
            f"cunoscut: {match.signature_name}. functioneaza DOAR pe trafic "
            f"necriptat - traficul HTTPS/TLS ramane opac acestei semnaturi, "
            f"la fel ca oricarui NIDS bazat pe retea"
        ),
        dest_ip=match.dst_ip,
        dest_port=match.dst_port,
    )


def scan_payload_sample(
    sample: PayloadSample, signatures: list[PayloadSignature] | None = None
) -> PayloadMatch | None:
    """potrivire simpla de subsir de octeti (nu regex, nu Aho-Corasick -
    un set mic de semnaturi nu justifica un motor mai complex).

    LIMITARE REALA, nu doar a acestei implementari: nu decripteaza si nu
    poate vedea nimic in traficul HTTPS/TLS (majoritatea traficului
    modern) - inspectia de payload la nivel de retea functioneaza doar
    pe trafic necriptat. un antivirus/EDR rulat pe host vede payload-ul
    DUPA decriptare, un NIDS network-based, ca acesta, nu poate"""
    sigs = signatures if signatures is not None else DEFAULT_PAYLOAD_SIGNATURES
    for sig in sigs:
        if sig.pattern in sample.payload:
            return PayloadMatch(
                src_ip=sample.src_ip,
                dst_ip=sample.dst_ip,
                dst_port=sample.dst_port,
                signature_name=sig.name,
            )
    return None


def detect_payload_signatures(
    samples: list[PayloadSample], signatures: list[PayloadSignature] | None = None
) -> list[PayloadMatch]:
    matches = []
    reported: set[tuple[str, str, int | None, str]] = set()
    for sample in samples:
        match = scan_payload_sample(sample, signatures)
        if match is None:
            continue
        key = (match.src_ip, match.dst_ip, match.dst_port, match.signature_name)
        if key in reported:
            continue
        reported.add(key)
        matches.append(match)
    return matches


class PayloadSignatureTracker:
    """varianta live (streaming) - acelasi principiu, aplicat esantion cu
    esantion pe masura ce sosesc din captura live"""

    def __init__(self, signatures: list[PayloadSignature] | None = None) -> None:
        self._signatures = signatures if signatures is not None else DEFAULT_PAYLOAD_SIGNATURES
        self._reported: set[tuple[str, str, int | None, str]] = set()

    def process_sample(self, sample: PayloadSample) -> Event | None:
        match = scan_payload_sample(sample, self._signatures)
        if match is None:
            return None
        key = (match.src_ip, match.dst_ip, match.dst_port, match.signature_name)
        if key in self._reported:
            return None
        self._reported.add(key)
        return event_from_payload_match(match)
