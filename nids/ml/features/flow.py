from __future__ import annotations

from dataclasses import dataclass, field

from nids.capture.packet_meta import PacketMeta

FlowKey = tuple[str, str, int | None, int | None, str]


@dataclass
class FlowFeatures:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    packet_count: int
    total_bytes: int
    duration: float
    mean_packet_size: float
    packets_per_second: float


@dataclass
class _FlowAccumulator:
    packet_count: int = 0
    total_bytes: int = 0
    first_ts: float = field(default=0.0)
    last_ts: float = field(default=0.0)


def _flow_key(pkt: PacketMeta) -> FlowKey:
    return (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)


def extract_flows(packets: list[PacketMeta]) -> list[FlowFeatures]:
    """grupeaza pachetele pe 5-tuple (sursa, destinatie, porturi, protocol)
    - fiecare combinatie e o conexiune/flux distinct - si calculeaza
    caracteristici agregate per flux, folosite ca input pentru modelele ML
    (nu per-pachet individual, care e prea zgomotos)"""
    accumulators: dict[FlowKey, _FlowAccumulator] = {}

    for pkt in packets:
        key = _flow_key(pkt)
        acc = accumulators.get(key)
        if acc is None:
            acc = _FlowAccumulator(first_ts=pkt.timestamp, last_ts=pkt.timestamp)
            accumulators[key] = acc

        acc.packet_count += 1
        acc.total_bytes += pkt.length
        acc.first_ts = min(acc.first_ts, pkt.timestamp)
        acc.last_ts = max(acc.last_ts, pkt.timestamp)

    return [_to_features(key, acc) for key, acc in accumulators.items()]


def _to_features(key: FlowKey, acc: _FlowAccumulator) -> FlowFeatures:
    src_ip, dst_ip, src_port, dst_port, protocol = key
    duration = acc.last_ts - acc.first_ts
    mean_packet_size = acc.total_bytes / acc.packet_count
    packets_per_second = acc.packet_count / duration if duration > 0 else float(acc.packet_count)

    return FlowFeatures(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_count=acc.packet_count,
        total_bytes=acc.total_bytes,
        duration=duration,
        mean_packet_size=mean_packet_size,
        packets_per_second=packets_per_second,
    )
