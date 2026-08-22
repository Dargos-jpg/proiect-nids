from __future__ import annotations

from dataclasses import asdict, dataclass

import pandas as pd

from nids.capture.packet_meta import PacketMeta
from nids.ml.features.connection import ConnectionFeatures, extract_connections
from nids.ml.features.traffic_window import TrafficWindowFeatures, TrafficWindowTracker


@dataclass
class NslKddStyleFeatures:
    # "basic" (9)
    duration: float
    protocol_type: str
    service: str
    flag: str
    src_bytes: int
    dst_bytes: int
    land: bool
    wrong_fragment: int
    urgent: int
    # "traffic" (19)
    count: int
    srv_count: int
    serror_rate: float
    srv_serror_rate: float
    rerror_rate: float
    srv_rerror_rate: float
    same_srv_rate: float
    diff_srv_rate: float
    srv_diff_host_rate: float
    dst_host_count: int
    dst_host_srv_count: int
    dst_host_same_srv_rate: float
    dst_host_diff_srv_rate: float
    dst_host_same_src_port_rate: float
    dst_host_srv_diff_host_rate: float
    dst_host_serror_rate: float
    dst_host_srv_serror_rate: float
    dst_host_rerror_rate: float
    dst_host_srv_rerror_rate: float
    # identificare - nu e feature ML, util pentru afisare/debugging
    src_ip: str
    dst_ip: str


def extract_nsl_kdd_style_features(packets: list[PacketMeta]) -> list[NslKddStyleFeatures]:
    """extrage cele 28 de features (9 'basic' + 19 'traffic') din cele 41
    din NSL-KDD, aproximate din pachetele capturate. celelalte 13
    ('content') raman neacoperite - cer inspectarea payload-ului
    aplicatiei (login-uri, comenzi shell), majoritatea traficului modern
    e criptat oricum. vezi NOTES.md"""
    connections = extract_connections(packets)
    connections.sort(key=lambda c: c.start_time)

    tracker = TrafficWindowTracker()
    return [_combine(conn, tracker.process(conn)) for conn in connections]


def _combine(conn: ConnectionFeatures, traffic: TrafficWindowFeatures) -> NslKddStyleFeatures:
    return NslKddStyleFeatures(
        duration=conn.duration,
        protocol_type=conn.protocol,
        service=conn.service,
        flag=conn.flag,
        src_bytes=conn.src_bytes,
        dst_bytes=conn.dst_bytes,
        land=conn.land,
        wrong_fragment=conn.wrong_fragment,
        urgent=conn.urgent,
        count=traffic.count,
        srv_count=traffic.srv_count,
        serror_rate=traffic.serror_rate,
        srv_serror_rate=traffic.srv_serror_rate,
        rerror_rate=traffic.rerror_rate,
        srv_rerror_rate=traffic.srv_rerror_rate,
        same_srv_rate=traffic.same_srv_rate,
        diff_srv_rate=traffic.diff_srv_rate,
        srv_diff_host_rate=traffic.srv_diff_host_rate,
        dst_host_count=traffic.dst_host_count,
        dst_host_srv_count=traffic.dst_host_srv_count,
        dst_host_same_srv_rate=traffic.dst_host_same_srv_rate,
        dst_host_diff_srv_rate=traffic.dst_host_diff_srv_rate,
        dst_host_same_src_port_rate=traffic.dst_host_same_src_port_rate,
        dst_host_srv_diff_host_rate=traffic.dst_host_srv_diff_host_rate,
        dst_host_serror_rate=traffic.dst_host_serror_rate,
        dst_host_srv_serror_rate=traffic.dst_host_srv_serror_rate,
        dst_host_rerror_rate=traffic.dst_host_rerror_rate,
        dst_host_srv_rerror_rate=traffic.dst_host_srv_rerror_rate,
        src_ip=conn.src_ip,
        dst_ip=conn.dst_ip,
    )


def to_feature_frame(records: list[NslKddStyleFeatures]) -> pd.DataFrame:
    """converteste in DataFrame-ul brut (neencodat) pe care il asteapta
    nids.ml.expert.nsl_kdd.encode_features - exclude src_ip/dst_ip
    (identificare, nu feature) si converteste land din bool in int, ca
    in coloana originala NSL-KDD"""
    rows = []
    for r in records:
        row = asdict(r)
        del row["src_ip"]
        del row["dst_ip"]
        row["land"] = int(row["land"])
        rows.append(row)
    return pd.DataFrame(rows)
