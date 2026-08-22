from __future__ import annotations

import threading
from collections.abc import Callable

from scapy.all import IP, sniff

from nids.capture.packet_meta import PacketMeta, extract_meta

_STOP_POLL_INTERVAL = 1.0


def capture_live(
    on_packet: Callable[[PacketMeta], None],
    interface: str | None = None,
    count: int = 0,
    timeout: float | None = None,
    stop_event: threading.Event | None = None,
) -> None:
    """asculta trafic live si apeleaza on_packet pentru fiecare pachet IP.
    necesita Npcap instalat; merge fara admin daca driverul nu a fost
    restrictionat la instalare.

    daca se da stop_event (folosit din UI, thread separat), captura ruleaza
    in bucla, in reprize scurte, ca sa poata fi oprita si pe retea linistita
    - scapy verifica stop_filter doar cand vine un pachet, deci o singura
    captura fara limita de timp ar putea ramane blocata la infinit"""

    def _handle(pkt) -> None:
        if IP in pkt:
            on_packet(extract_meta(pkt))

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
