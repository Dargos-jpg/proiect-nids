from __future__ import annotations

from dataclasses import dataclass

from nids.capture.packet_meta import PacketMeta
from nids.ml.features.service_names import service_name

_Endpoint = tuple[str, int | None]
_ConnectionKey = tuple[tuple[_Endpoint, _Endpoint], str]


@dataclass
class ConnectionFeatures:
    """cele 9 features 'basic' din NSL-KDD, calculate per conexiune
    (perechea de capete, indiferent de directie - nu per pachet)"""

    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    service: str
    flag: str
    start_time: float
    duration: float
    src_bytes: int
    dst_bytes: int
    land: bool
    wrong_fragment: int
    urgent: int


def _connection_key(pkt: PacketMeta) -> _ConnectionKey:
    a: _Endpoint = (pkt.src_ip, pkt.src_port)
    b: _Endpoint = (pkt.dst_ip, pkt.dst_port)
    pair = (a, b) if a <= b else (b, a)
    return (pair, pkt.protocol)


def extract_connections(packets: list[PacketMeta]) -> list[ConnectionFeatures]:
    """grupeaza pachetele pe conexiune (ambele directii impreuna, spre
    deosebire de flow.py care grupeaza per directie) - necesar ca sa
    calculam corect src_bytes/dst_bytes, care descriu explicit cele
    doua directii ale aceleiasi conexiuni"""
    groups: dict[_ConnectionKey, list[PacketMeta]] = {}
    for pkt in packets:
        groups.setdefault(_connection_key(pkt), []).append(pkt)

    connections = []
    for pkts in groups.values():
        pkts.sort(key=lambda p: p.timestamp)
        connections.append(_build_connection(pkts))
    return connections


def _build_connection(pkts: list[PacketMeta]) -> ConnectionFeatures:
    origin = pkts[0]
    src_ip, src_port = origin.src_ip, origin.src_port
    dst_ip, dst_port = origin.dst_ip, origin.dst_port
    protocol = origin.protocol

    src_bytes = 0
    dst_bytes = 0
    urgent = 0
    wrong_fragment = 0
    seen_flags: set[str] = set()

    for pkt in pkts:
        if pkt.src_ip == src_ip and pkt.src_port == src_port:
            src_bytes += pkt.length
        else:
            dst_bytes += pkt.length

        if pkt.is_fragmented:
            wrong_fragment += 1
        if pkt.tcp_flags:
            seen_flags.add(pkt.tcp_flags)
            if "U" in pkt.tcp_flags:
                urgent += 1

    return ConnectionFeatures(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        service=service_name(protocol, dst_port),
        flag=_connection_flag(protocol, seen_flags),
        start_time=pkts[0].timestamp,
        duration=pkts[-1].timestamp - pkts[0].timestamp,
        src_bytes=src_bytes,
        dst_bytes=dst_bytes,
        land=src_ip == dst_ip and src_port == dst_port,
        wrong_fragment=wrong_fragment,
        urgent=urgent,
    )


def _connection_flag(protocol: str, seen_flags: set[str]) -> str:
    """aproximare simplificata a starii conexiunii TCP - nu replica exact
    taxonomia originala NSL-KDD (SF/S0/S1/S2/S3/REJ/RSTO/RSTR/...), doar
    distinge cazurile principale: conexiune normala, fara raspuns, sau
    respinsa/intrerupta. suficient de utila pentru modelul propriu"""
    if protocol != "tcp":
        return "SF"

    has_syn = any("S" in f for f in seen_flags)
    has_synack = "SA" in seen_flags
    has_reset = any("R" in f for f in seen_flags)
    has_fin = any("F" in f for f in seen_flags)

    if has_reset:
        return "REJ" if not has_synack else "RSTO"
    if has_syn and not has_synack:
        return "S0"
    if has_syn and has_synack and has_fin:
        return "SF"
    if has_syn and has_synack:
        return "S1"
    return "OTH"
