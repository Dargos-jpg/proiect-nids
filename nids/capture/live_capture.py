from __future__ import annotations

import threading
from collections.abc import Callable

from scapy.all import ARP, DNS, IP, sniff

from nids.capture.arp_meta import ArpFrame, extract_arp_frame
from nids.capture.dns_meta import DnsQuery, extract_dns_query
from nids.capture.packet_meta import PacketMeta, extract_meta
from nids.capture.payload_meta import PayloadSample, extract_payload_sample

_STOP_POLL_INTERVAL = 1.0


def capture_live(
    on_packet: Callable[[PacketMeta], None],
    on_arp: Callable[[ArpFrame], None] | None = None,
    on_dns: Callable[[DnsQuery], None] | None = None,
    on_payload: Callable[[PayloadSample], None] | None = None,
    interface: str | None = None,
    count: int = 0,
    timeout: float | None = None,
    stop_event: threading.Event | None = None,
) -> None:
    """asculta trafic live si apeleaza on_packet pentru fiecare pachet IP,
    on_arp pentru fiecare cadru ARP (protocol separat, sub IP - filtrat
    complet inainte, ARP spoofing nu putea fi detectat din on_packet),
    on_dns pentru fiecare INTEROGARE DNS (subset al pachetelor IP) si
    on_payload pentru fiecare pachet cu date de aplicatie (subset al
    pachetelor IP care au un strat Raw dupa TCP/UDP) - payload-ul nu e
    stocat nicaieri pe termen lung (spre deosebire de PacketMeta), doar
    trecut o singura data prin callback pentru scanare de semnaturi.
    necesita Npcap instalat; merge fara admin daca driverul nu a fost
    restrictionat la instalare.

    daca se da stop_event (folosit din UI, thread separat), captura ruleaza
    in bucla, in reprize scurte, ca sa poata fi oprita si pe retea linistita
    - scapy verifica stop_filter doar cand vine un pachet, deci o singura
    captura fara limita de timp ar putea ramane blocata la infinit"""

    def _handle(pkt) -> None:
        if IP in pkt:
            on_packet(extract_meta(pkt))
            if on_dns is not None and DNS in pkt:
                query = extract_dns_query(pkt)
                if query is not None:
                    on_dns(query)
            if on_payload is not None:
                sample = extract_payload_sample(pkt)
                if sample is not None:
                    on_payload(sample)
        elif on_arp is not None and ARP in pkt:
            on_arp(extract_arp_frame(pkt))

    if stop_event is None:
        sniff(iface=interface, prn=_handle, count=count, timeout=timeout, store=False)
        return

    while not stop_event.is_set():
        sniff(
            iface=interface,
            prn=_handle,
            timeout=_STOP_POLL_INTERVAL,
            store=False,
            stop_filter=lambda pkt: stop_event.is_set(),
        )
