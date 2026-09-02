from __future__ import annotations

import selectors
import socket
import threading
from dataclasses import dataclass
from typing import Protocol

from nids.core.event import Event, Severity

_ACCEPT_BACKLOG = 5
_SELECT_TIMEOUT = 0.5  # cat de des verificam stop_event intre conexiuni
_CONNECTION_TIMEOUT = 2.0  # cat asteptam raspunsul clientului, dupa banner
_MAX_READ_BYTES = 256  # doar pentru context/log - NICIODATA interpretat/executat

# banner minim, doar ca sa para un serviciu real pentru cateva clipe -
# nu emuleaza protocolul real, nu proceseaza niciun raspuns al clientului
_BANNERS: dict[int, bytes] = {
    22: b"SSH-2.0-OpenSSH_8.9\r\n",
    23: b"\r\nlogin: ",
}


@dataclass
class HoneypotHit:
    src_ip: str
    src_port: int
    dst_port: int
    received_preview: str  # ce a trimis clientul, truncat - doar afisare/log


class _HitCallback(Protocol):
    def __call__(self, hit: HoneypotHit) -> None: ...


class _BindErrorCallback(Protocol):
    def __call__(self, port: int, message: str) -> None: ...


def event_from_honeypot_hit(hit: HoneypotHit) -> Event:
    """orice conexiune la un port-momeala e prin definitie suspecta -
    niciun serviciu legitim nu asculta acolo, deci nu exista conceptul de
    fals-pozitiv aici (spre deosebire de semnaturi/ML) - severitate HIGH
    mereu"""
    preview = f" - a trimis: {hit.received_preview!r}" if hit.received_preview else ""
    return Event(
        event_type="conexiune la honeypot",
        source_ip=hit.src_ip,
        severity=Severity.HIGH,
        description=(
            f"conexiune catre serviciul-momeala de pe portul {hit.dst_port} - "
            f"niciun serviciu real nu asculta acolo, orice contact e suspect{preview}"
        ),
        src_port=hit.src_port,
        dest_port=hit.dst_port,
    )


def run_honeypot(
    ports: list[int],
    on_hit: _HitCallback,
    on_bind_error: _BindErrorCallback,
    stop_event: threading.Event,
) -> None:
    """asculta simultan pe toate porturile date, intr-un singur thread
    (selectors, neblocant) - un thread scurt separat DOAR pentru
    gestionarea fiecarei conexiuni acceptate (trimite banner, citeste
    putin, inchide), ca o conexiune lenta sa nu blocheze acceptarea
    altora. gandit sa fie corpul unic al QThread.run() (vezi HoneypotThread),
    la fel ca live_capture/simulation - un singur apel blocant de lunga
    durata, nu o serie de sarcini scurte.

    NU emuleaza protocolul real dincolo de un banner static, NU
    proceseaza/executa NIMIC din ce trimite clientul - doar logheaza.
    porturile mari (>1024, ex: 2222/8080) nu cer drepturi de administrator,
    spre deosebire de blocarea de firewall"""
    selector = selectors.DefaultSelector()
    servers: list[socket.socket] = []

    for port in ports:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", port))
            server.listen(_ACCEPT_BACKLOG)
            server.setblocking(False)
        except OSError as exc:
            on_bind_error(port, str(exc))
            continue
        selector.register(server, selectors.EVENT_READ, port)
        servers.append(server)

    try:
        while not stop_event.is_set() and servers:
            for key, _ in selector.select(timeout=_SELECT_TIMEOUT):
                server = key.fileobj
                port = key.data
                try:
                    conn, addr = server.accept()
                except OSError:
                    continue
                threading.Thread(
                    target=_handle_connection,
                    args=(conn, addr, port, on_hit),
                    daemon=True,
                ).start()
    finally:
        for server in servers:
            selector.unregister(server)
            server.close()
        selector.close()


def _handle_connection(
    conn: socket.socket, addr: tuple[str, int], port: int, on_hit: _HitCallback
) -> None:
    src_ip, src_port = addr[0], addr[1]
    preview = ""
    try:
        banner = _BANNERS.get(port, b"")
        if banner:
            conn.sendall(banner)
        conn.settimeout(_CONNECTION_TIMEOUT)
        try:
            data = conn.recv(_MAX_READ_BYTES)
            preview = data.decode("utf-8", errors="replace")
        except OSError:
            pass
    finally:
        conn.close()

    on_hit(HoneypotHit(src_ip=src_ip, src_port=src_port, dst_port=port, received_preview=preview))
