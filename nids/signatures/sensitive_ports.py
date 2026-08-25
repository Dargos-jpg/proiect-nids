from __future__ import annotations

from dataclasses import dataclass

from nids.capture.packet_meta import PacketMeta
from nids.core.event import Event, Severity

# SSH, Telnet, RDP, SMB - servicii tinta comune pentru acces neautorizat.
# editabila din UI (SignaturesPanel) - asta e doar valoarea implicita
DEFAULT_SENSITIVE_PORTS: set[int] = {22, 23, 445, 3389}


@dataclass
class SensitivePortEvent:
    src_ip: str
    dst_ip: str
    port: int


def event_from_sensitive_port(evt: SensitivePortEvent) -> Event:
    return Event(
        event_type="contact port sensibil",
        source_ip=evt.src_ip,
        severity=Severity.HIGH,
        description=(
            f"conexiune catre portul sensibil {evt.port} pe {evt.dst_ip} - "
            "semnalat imediat, indiferent de pragul de port scan"
        ),
        dest_ip=evt.dst_ip,
        dest_port=evt.port,
    )


def detect_sensitive_port_contacts(
    packets: list[PacketMeta], sensitive_ports: set[int]
) -> list[SensitivePortEvent]:
    """gaseste, intr-un PCAP static, orice contact catre un port din
    lista de porturi sensibile - o SINGURA conexiune catre un port
    critic (SSH/RDP/SMB) e semnal suficient, spre deosebire de port scan
    care are nevoie de mai multe porturi distincte ca sa depaseasca
    pragul. rezolva golul semnalat: un atacator care tinteste doar 2-3
    porturi critice, sub pragul de port scan, ar trece neobservat"""
    if not sensitive_ports:
        return []

    seen: set[tuple[str, str, int]] = set()
    events = []
    for pkt in packets:
        if pkt.dst_port not in sensitive_ports:
            continue
        key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port)
        if key in seen:
            continue
        seen.add(key)
        events.append(SensitivePortEvent(src_ip=pkt.src_ip, dst_ip=pkt.dst_ip, port=pkt.dst_port))
    return events


class SensitivePortTracker:
    """varianta live (streaming) a detect_sensitive_port_contacts - un
    contact catre un port sensibil e raportat o singura data per (sursa,
    destinatie, port) pe sesiune, imediat la primul pachet, fara sa
    astepte niciun prag"""

    def __init__(self, sensitive_ports: set[int]) -> None:
        self._sensitive_ports = sensitive_ports
        self._seen: set[tuple[str, str, int]] = set()

    def process_packet(self, pkt: PacketMeta) -> Event | None:
        if pkt.dst_port not in self._sensitive_ports:
            return None
        key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port)
        if key in self._seen:
            return None
        self._seen.add(key)
        return event_from_sensitive_port(
            SensitivePortEvent(src_ip=pkt.src_ip, dst_ip=pkt.dst_ip, port=pkt.dst_port)
        )
