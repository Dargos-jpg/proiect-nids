from __future__ import annotations

import socket

DEFAULT_SIMULATION_PORTS = [21, 22, 23, 25, 3389, 8080, 8443, 9000]


def local_ip() -> str:
    """IP-ul propriu pe reteaua locala - tinta implicita pentru
    simulare. NU 127.0.0.1: traficul catre loopback ramane in kernel si
    nu ajunge la interfata de retea reala, deci Npcap nu l-ar vedea"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))  # nu trimite nimic, doar afla ruta locala
        return sock.getsockname()[0]
    finally:
        sock.close()


def run_port_scan_simulation(
    target_ip: str | None = None, ports: list[int] = DEFAULT_SIMULATION_PORTS
) -> str:
    """incearca conexiuni TCP scurte catre mai multe porturi ale
    target_ip (implicit propriul IP din reteaua locala) - safe, doar
    incercari de conexiune; esecul e asteptat si normal pentru porturile
    inchise. genereaza trafic real care declanseaza semnatura de port
    scan daca monitorizarea live ruleaza in paralel. vezi CONTEXT-nids.md,
    "mod de simulare (...) utilizatorul vede sistemul reactionand live" """
    target_ip = target_ip or local_ip()

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            sock.connect_ex((target_ip, port))
        finally:
            sock.close()

    return target_ip
