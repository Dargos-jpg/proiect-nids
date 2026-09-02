from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from nids.capture.dns_meta import DnsQuery
from nids.core.event import Event, Severity

# praguri euristice, nu calibrate statistic pe trafic real - text normal
# (nume de domenii alese de oameni) are de regula entropie sub ~3 biti pe
# caracter; date encodate base32/base64/hex (ce foloseste tunneling-ul ca
# sa "ascunda" continut in subdomenii) se apropie de 4+ biti pe caracter.
# lungimea filtreaza etichete scurte, unde entropia oricum nu inseamna
# nimic statistic (o eticheta de 5 caractere poate avea entropie mare din
# intamplare)
DEFAULT_MIN_LABEL_LENGTH = 30
DEFAULT_MIN_ENTROPY = 3.5


@dataclass
class DnsTunnelEvent:
    src_ip: str
    query_name: str
    reason: str


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _suspicious_reason(query_name: str, min_label_length: int, min_entropy: float) -> str | None:
    """eticheta = prima parte a numelui, inainte de primul punct - acolo
    codeaza tunneling-ul de obicei datele, restul e domeniul de baza
    controlat de atacator (ex: <date encodate>.exfil.atacator.com)

    fals-pozitive REALE gasite de user: domenii tehnice legitime, lungi,
    compuse din cuvinte cu cratima (ex: "launcher-public-service-prod06"
    de la Epic Games, "service-aggregation-layer-subs" de la EA) - au
    lungime si entropie la fel de mari ca date chiar encodate (entropia
    singura nu le separa curat, cratima ridica entropia aproape la fel
    de mult ca encodarea). fix: tunneling-ul real foloseste aproape mereu
    base32 sau hex (NU base64 - nu supravietuieste case-insensitivity-ul
    DNS) - niciuna din aceste alfabete nu contine cratima sau alte
    separatoare. o eticheta cu orice caracter non-alfanumeric e aproape
    sigur un nume ales de un om/serviciu, nu date encodate"""
    label = query_name.split(".")[0]
    if len(label) < min_label_length:
        return None
    if not label.isalnum():
        return None
    entropy = _shannon_entropy(label)
    if entropy < min_entropy:
        return None
    preview = label if len(label) <= 24 else f"{label[:24]}..."
    return f"eticheta '{preview}' - {len(label)} caractere, entropie {entropy:.2f} biti/caracter"


def event_from_dns_tunnel(evt: DnsTunnelEvent) -> Event:
    return Event(
        event_type="posibil DNS tunneling",
        source_ip=evt.src_ip,
        severity=Severity.MEDIUM,
        description=(
            f"interogare DNS neobisnuita catre {evt.query_name} - {evt.reason}. "
            f"posibil exfiltrare de date sau canal de comanda-si-control prin DNS"
        ),
    )


def detect_dns_tunneling(
    queries: list[DnsQuery],
    min_label_length: int = DEFAULT_MIN_LABEL_LENGTH,
    min_entropy: float = DEFAULT_MIN_ENTROPY,
) -> list[DnsTunnelEvent]:
    """euristica clasica pentru DNS tunneling: etichete de subdomeniu
    lungi SI cu entropie mare (arata a date encodate, nu a text ales de
    un om) - nu emuleaza niciun protocol, doar analizeaza STRUCTURA
    numelui interogat (DNS necriptat, deci vizibil, spre deosebire de
    HTTPS). fals-pozitive posibile: nume de fisiere/hash-uri legitime in
    subdomenii (CDN-uri, servicii cloud) - la fel ca orice euristica
    comportamentala, nu de continut cunoscut"""
    events = []
    reported: set[tuple[str, str]] = set()
    for query in queries:
        reason = _suspicious_reason(query.query_name, min_label_length, min_entropy)
        if reason is None:
            continue
        key = (query.src_ip, query.query_name)
        if key in reported:
            continue
        reported.add(key)
        events.append(DnsTunnelEvent(src_ip=query.src_ip, query_name=query.query_name, reason=reason))
    return events


class DnsTunnelTracker:
    """varianta live (streaming) - acelasi principiu, aplicat interogare
    cu interogare pe masura ce sosesc din captura live"""

    def __init__(
        self,
        min_label_length: int = DEFAULT_MIN_LABEL_LENGTH,
        min_entropy: float = DEFAULT_MIN_ENTROPY,
    ) -> None:
        self._min_label_length = min_label_length
        self._min_entropy = min_entropy
        self._reported: set[tuple[str, str]] = set()

    def process_query(self, query: DnsQuery) -> Event | None:
        reason = _suspicious_reason(query.query_name, self._min_label_length, self._min_entropy)
        if reason is None:
            return None
        key = (query.src_ip, query.query_name)
        if key in self._reported:
            return None
        self._reported.add(key)
        return event_from_dns_tunnel(
            DnsTunnelEvent(src_ip=query.src_ip, query_name=query.query_name, reason=reason)
        )
