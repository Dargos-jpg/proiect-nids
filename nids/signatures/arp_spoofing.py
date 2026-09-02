from __future__ import annotations

from dataclasses import dataclass

from nids.capture.arp_meta import ArpFrame
from nids.core.event import Event, Severity


@dataclass
class ArpSpoofEvent:
    ip: str
    original_mac: str
    new_mac: str


def event_from_arp_spoof(evt: ArpSpoofEvent) -> Event:
    return Event(
        event_type="ARP spoofing",
        source_ip=evt.ip,
        severity=Severity.HIGH,
        description=(
            f"adresa {evt.ip} era asociata cu MAC {evt.original_mac}, dar a "
            f"aparut trafic ARP care o revendica din partea MAC {evt.new_mac} - "
            f"posibil ARP spoofing (interceptare de trafic in reteaua locala)"
        ),
    )


def detect_arp_spoofing(frames: list[ArpFrame]) -> list[ArpSpoofEvent]:
    """urmareste legaturile IP<->MAC asa cum sunt afirmate de traficul ARP,
    in ordine cronologica - daca aceeasi adresa IP e revendicata ulterior
    de un MAC DIFERIT, e semnalul clasic de ARP spoofing (cineva incearca
    sa intercepteze traficul destinat acelei adrese, poison-uind cache-ul
    ARP al retelei). PRIMA legatura vazuta pentru o adresa e considerata
    de incredere (nu exista un "adevar" extern - ex. un server DHCP - cu
    care sa comparam), orice schimbare ulterioara e suspecta.

    limitare cunoscuta si asumata: exista si motive LEGITIME pentru
    schimbarea unui MAC asociat unei adrese (inlocuire placa de retea,
    migrare masina virtuala, realocare DHCP) - un fals-pozitiv posibil,
    la fel ca la orice semnatura bazata pe comportament, nu pe continut"""
    frames_sorted = sorted(frames, key=lambda f: f.timestamp)
    known: dict[str, str] = {}
    reported: set[tuple[str, str]] = set()
    events = []

    for frame in frames_sorted:
        existing_mac = known.get(frame.sender_ip)
        if existing_mac is None:
            known[frame.sender_ip] = frame.sender_mac
            continue
        if existing_mac == frame.sender_mac:
            continue

        key = (frame.sender_ip, frame.sender_mac)
        known[frame.sender_ip] = frame.sender_mac
        if key in reported:
            continue
        reported.add(key)
        events.append(
            ArpSpoofEvent(ip=frame.sender_ip, original_mac=existing_mac, new_mac=frame.sender_mac)
        )

    return events


class ArpSpoofTracker:
    """varianta live (streaming) - acelasi principiu ca detect_arp_spoofing,
    dar actualizat cadru cu cadru, pe masura ce sosesc din captura live"""

    def __init__(self) -> None:
        self._known: dict[str, str] = {}
        self._reported: set[tuple[str, str]] = set()

    def process_frame(self, frame: ArpFrame) -> Event | None:
        existing_mac = self._known.get(frame.sender_ip)
        if existing_mac is None:
            self._known[frame.sender_ip] = frame.sender_mac
            return None
        if existing_mac == frame.sender_mac:
            return None

        key = (frame.sender_ip, frame.sender_mac)
        self._known[frame.sender_ip] = frame.sender_mac
        if key in self._reported:
            return None
        self._reported.add(key)
        return event_from_arp_spoof(
            ArpSpoofEvent(ip=frame.sender_ip, original_mac=existing_mac, new_mac=frame.sender_mac)
        )
