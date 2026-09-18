from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass, field

import pandas as pd

from nids.capture.packet_meta import PacketMeta

_Endpoint = tuple[str, int | None]
_FlowKey = tuple[tuple[_Endpoint, _Endpoint], str]

# prag pentru segmentarea unui flux in rafale "active" separate de pauze
# "idle" - 5 secunde, valoarea implicita documentata pentru CICFlowMeter.
# NU exista o specificatie publica exacta a algoritmului original (Java) -
# la fel ca taxonomia de flag-uri NSL-KDD (_connection_flag in connection.py),
# asta e o interpretare proprie, consistenta, nu o replica byte-cu-byte
IDLE_THRESHOLD_SECONDS = 5.0

# lungimi de header aproximate (fara optiuni IP/TCP) - PacketMeta nu retine
# header-ul exact, doar dimensiunea totala a pachetului. aproximare
# rezonabila: majoritatea traficului modern nu foloseste optiuni IP/TCP
_IP_HEADER_BYTES = 20
_TCP_HEADER_BYTES = 20
_UDP_HEADER_BYTES = 8


@dataclass
class CicFlowFeatures:
    """aproximare a celor 80 de coloane CICFlowMeter din CSE-CIC-IDS2018,
    derivata din PacketMeta - vezi DATASET-COMPARISON.md pentru analiza
    completa (ce s-a putut calcula direct, ce a cerut extindere de
    PacketMeta, ce a cerut logica noua, ce s-a exclus si de ce).

    schema COMPLET separata de nids.ml.features.nsl_kdd_style - al doilea
    model expert (CSE-CIC-IDS2018) nu imprumuta nimic din cel vechi
    (NSL-KDD), ruleaza in paralel, nu il inlocuieste"""

    # identificare - nu toate sunt features (vezi to_feature_frame), dar
    # dst_port SI protocol chiar sunt features in schema originala
    # CICFlowMeter (spre deosebire de NSL-KDD, unde portul nu e feature
    # direct, doar "service"-ul derivat din el)
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str

    flow_duration: float
    tot_fwd_pkts: int
    tot_bwd_pkts: int
    totlen_fwd_pkts: int
    totlen_bwd_pkts: int
    fwd_pkt_len_max: float
    fwd_pkt_len_min: float
    fwd_pkt_len_mean: float
    fwd_pkt_len_std: float
    bwd_pkt_len_max: float
    bwd_pkt_len_min: float
    bwd_pkt_len_mean: float
    bwd_pkt_len_std: float
    flow_byts_per_s: float
    flow_pkts_per_s: float
    flow_iat_mean: float
    flow_iat_std: float
    flow_iat_max: float
    flow_iat_min: float
    fwd_iat_tot: float
    fwd_iat_mean: float
    fwd_iat_std: float
    fwd_iat_max: float
    fwd_iat_min: float
    bwd_iat_tot: float
    bwd_iat_mean: float
    bwd_iat_std: float
    bwd_iat_max: float
    bwd_iat_min: float
    fwd_psh_flags: int
    bwd_psh_flags: int
    fwd_urg_flags: int
    bwd_urg_flags: int
    fwd_header_len: int
    bwd_header_len: int
    fwd_pkts_per_s: float
    bwd_pkts_per_s: float
    pkt_len_min: float
    pkt_len_max: float
    pkt_len_mean: float
    pkt_len_std: float
    pkt_len_var: float
    fin_flag_cnt: int
    syn_flag_cnt: int
    rst_flag_cnt: int
    psh_flag_cnt: int
    ack_flag_cnt: int
    urg_flag_cnt: int
    cwe_flag_cnt: int
    ece_flag_cnt: int
    down_up_ratio: float
    pkt_size_avg: float
    fwd_seg_size_avg: float
    bwd_seg_size_avg: float
    subflow_fwd_pkts: float
    subflow_fwd_byts: float
    subflow_bwd_pkts: float
    subflow_bwd_byts: float
    init_fwd_win_byts: int
    init_bwd_win_byts: int
    fwd_act_data_pkts: int
    fwd_seg_size_min: float
    active_mean: float
    active_std: float
    active_max: float
    active_min: float
    idle_mean: float
    idle_std: float
    idle_max: float
    idle_min: float


def _flow_key(pkt: PacketMeta) -> _FlowKey:
    """grupare bidirectionala (ambele directii ale aceluiasi schimb in
    ACELASI flux) - identic ca principiu cu _connection_key din
    connection.py. directia "forward"/"backward" se decide separat, in
    _build_flow, dupa PRIMUL pachet cronologic - nu dupa sortarea
    lexicografica folosita aici doar pentru grupare"""
    a: _Endpoint = (pkt.src_ip, pkt.src_port)
    b: _Endpoint = (pkt.dst_ip, pkt.dst_port)
    pair = (a, b) if a <= b else (b, a)
    return (pair, pkt.protocol)


def extract_cicflow_features(packets: list[PacketMeta]) -> list[CicFlowFeatures]:
    groups: dict[_FlowKey, list[PacketMeta]] = {}
    for pkt in packets:
        groups.setdefault(_flow_key(pkt), []).append(pkt)

    flows = []
    for pkts in groups.values():
        pkts.sort(key=lambda p: p.timestamp)
        flows.append(_build_flow(pkts))
    return flows


def _has_flag(pkt: PacketMeta, letter: str) -> bool:
    return pkt.tcp_flags is not None and letter in pkt.tcp_flags


def _iat_stats(timestamps: list[float]) -> tuple[float, float, float, float, float]:
    """(total, mean, std, max, min) intre pachete CONSECUTIVE din lista
    data - sub 2 elemente => nimic de masurat, toate 0"""
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    diffs = [b - a for a, b in zip(timestamps, timestamps[1:])]
    mean = statistics.fmean(diffs)
    std = statistics.pstdev(diffs) if len(diffs) > 1 else 0.0
    return sum(diffs), mean, std, max(diffs), min(diffs)


def _len_stats(lengths: list[int]) -> tuple[float, float, float, float]:
    """(max, min, mean, std) - lista goala => toate 0"""
    if not lengths:
        return 0.0, 0.0, 0.0, 0.0
    mean = statistics.fmean(lengths)
    std = statistics.pstdev(lengths) if len(lengths) > 1 else 0.0
    return float(max(lengths)), float(min(lengths)), mean, std


def _segment_bursts(
    timestamps: list[float], idle_threshold: float = IDLE_THRESHOLD_SECONDS
) -> tuple[list[float], list[float]]:
    """imparte o secventa de timestamp-uri SORTATE in rafale "active"
    separate de pauze >= idle_threshold - intoarce (durate_active,
    durate_idle). un flux fara nicio pauza mare are o singura rafala
    (durata = durata totala a fluxului) si nicio pauza idle"""
    if not timestamps:
        return [], []

    active_durations = []
    idle_durations = []
    burst_start = timestamps[0]
    prev = timestamps[0]
    for t in timestamps[1:]:
        gap = t - prev
        if gap >= idle_threshold:
            active_durations.append(prev - burst_start)
            idle_durations.append(gap)
            burst_start = t
        prev = t
    active_durations.append(prev - burst_start)
    return active_durations, idle_durations


def _stats4(values: list[float]) -> tuple[float, float, float, float]:
    """(mean, std, max, min) - lista goala => toate 0"""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    mean = statistics.fmean(values)
    std = statistics.pstdev(values) if len(values) > 1 else 0.0
    return mean, std, max(values), min(values)


def _build_flow(pkts: list[PacketMeta]) -> CicFlowFeatures:
    origin = pkts[0]
    fwd_endpoint = (origin.src_ip, origin.src_port)

    fwd_pkts = [p for p in pkts if (p.src_ip, p.src_port) == fwd_endpoint]
    bwd_pkts = [p for p in pkts if (p.src_ip, p.src_port) != fwd_endpoint]

    start_time = pkts[0].timestamp
    end_time = pkts[-1].timestamp
    flow_duration = end_time - start_time

    fwd_lengths = [p.length for p in fwd_pkts]
    bwd_lengths = [p.length for p in bwd_pkts]
    all_lengths = [p.length for p in pkts]

    totlen_fwd = sum(fwd_lengths)
    totlen_bwd = sum(bwd_lengths)

    fwd_pkt_len_max, fwd_pkt_len_min, fwd_pkt_len_mean, fwd_pkt_len_std = _len_stats(fwd_lengths)
    bwd_pkt_len_max, bwd_pkt_len_min, bwd_pkt_len_mean, bwd_pkt_len_std = _len_stats(bwd_lengths)

    flow_iat_tot, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _iat_stats(
        [p.timestamp for p in pkts]
    )
    fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _iat_stats(
        [p.timestamp for p in fwd_pkts]
    )
    bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _iat_stats(
        [p.timestamp for p in bwd_pkts]
    )

    pkt_len_max, pkt_len_min, pkt_len_mean, pkt_len_std = _len_stats(all_lengths)
    pkt_len_var = pkt_len_std**2

    def _header_bytes(count: int, protocol: str) -> int:
        transport = _TCP_HEADER_BYTES if protocol == "tcp" else _UDP_HEADER_BYTES
        return count * (_IP_HEADER_BYTES + transport)

    def _first_window(packets_: list[PacketMeta]) -> int:
        for p in packets_:
            if p.tcp_window is not None:
                return p.tcp_window
        return -1  # la fel ca in datele reale CICFlowMeter, pentru fluxuri fara TCP

    active_durations, idle_durations = _segment_bursts([p.timestamp for p in pkts])
    num_subflows = max(len(active_durations), 1)
    active_mean, active_std, active_max, active_min = _stats4(active_durations)
    idle_mean, idle_std, idle_max, idle_min = _stats4(idle_durations)

    total_pkts = len(pkts)
    total_bytes = totlen_fwd + totlen_bwd

    return CicFlowFeatures(
        src_ip=origin.src_ip,
        dst_ip=origin.dst_ip,
        src_port=origin.src_port,
        dst_port=origin.dst_port,
        protocol=origin.protocol,
        flow_duration=flow_duration,
        tot_fwd_pkts=len(fwd_pkts),
        tot_bwd_pkts=len(bwd_pkts),
        totlen_fwd_pkts=totlen_fwd,
        totlen_bwd_pkts=totlen_bwd,
        fwd_pkt_len_max=fwd_pkt_len_max,
        fwd_pkt_len_min=fwd_pkt_len_min,
        fwd_pkt_len_mean=fwd_pkt_len_mean,
        fwd_pkt_len_std=fwd_pkt_len_std,
        bwd_pkt_len_max=bwd_pkt_len_max,
        bwd_pkt_len_min=bwd_pkt_len_min,
        bwd_pkt_len_mean=bwd_pkt_len_mean,
        bwd_pkt_len_std=bwd_pkt_len_std,
        flow_byts_per_s=total_bytes / flow_duration if flow_duration > 0 else 0.0,
        flow_pkts_per_s=total_pkts / flow_duration if flow_duration > 0 else 0.0,
        flow_iat_mean=flow_iat_mean,
        flow_iat_std=flow_iat_std,
        flow_iat_max=flow_iat_max,
        flow_iat_min=flow_iat_min,
        fwd_iat_tot=fwd_iat_tot,
        fwd_iat_mean=fwd_iat_mean,
        fwd_iat_std=fwd_iat_std,
        fwd_iat_max=fwd_iat_max,
        fwd_iat_min=fwd_iat_min,
        bwd_iat_tot=bwd_iat_tot,
        bwd_iat_mean=bwd_iat_mean,
        bwd_iat_std=bwd_iat_std,
        bwd_iat_max=bwd_iat_max,
        bwd_iat_min=bwd_iat_min,
        fwd_psh_flags=sum(1 for p in fwd_pkts if _has_flag(p, "P")),
        bwd_psh_flags=sum(1 for p in bwd_pkts if _has_flag(p, "P")),
        fwd_urg_flags=sum(1 for p in fwd_pkts if _has_flag(p, "U")),
        bwd_urg_flags=sum(1 for p in bwd_pkts if _has_flag(p, "U")),
        fwd_header_len=_header_bytes(len(fwd_pkts), origin.protocol),
        bwd_header_len=_header_bytes(len(bwd_pkts), origin.protocol),
        fwd_pkts_per_s=len(fwd_pkts) / flow_duration if flow_duration > 0 else 0.0,
        bwd_pkts_per_s=len(bwd_pkts) / flow_duration if flow_duration > 0 else 0.0,
        pkt_len_min=pkt_len_min,
        pkt_len_max=pkt_len_max,
        pkt_len_mean=pkt_len_mean,
        pkt_len_std=pkt_len_std,
        pkt_len_var=pkt_len_var,
        fin_flag_cnt=sum(1 for p in pkts if _has_flag(p, "F")),
        syn_flag_cnt=sum(1 for p in pkts if _has_flag(p, "S")),
        rst_flag_cnt=sum(1 for p in pkts if _has_flag(p, "R")),
        psh_flag_cnt=sum(1 for p in pkts if _has_flag(p, "P")),
        ack_flag_cnt=sum(1 for p in pkts if _has_flag(p, "A")),
        urg_flag_cnt=sum(1 for p in pkts if _has_flag(p, "U")),
        cwe_flag_cnt=sum(1 for p in pkts if _has_flag(p, "C")),
        ece_flag_cnt=sum(1 for p in pkts if _has_flag(p, "E")),
        down_up_ratio=len(bwd_pkts) / len(fwd_pkts) if fwd_pkts else 0.0,
        pkt_size_avg=total_bytes / total_pkts if total_pkts else 0.0,
        # redundant fata de fwd/bwd_pkt_len_mean prin definitie - CICFlowMeter
        # original are aceeasi redundanta (documentata in literatura academica)
        fwd_seg_size_avg=fwd_pkt_len_mean,
        bwd_seg_size_avg=bwd_pkt_len_mean,
        subflow_fwd_pkts=len(fwd_pkts) / num_subflows,
        subflow_fwd_byts=totlen_fwd / num_subflows,
        subflow_bwd_pkts=len(bwd_pkts) / num_subflows,
        subflow_bwd_byts=totlen_bwd / num_subflows,
        init_fwd_win_byts=_first_window(fwd_pkts),
        init_bwd_win_byts=_first_window(bwd_pkts),
        fwd_act_data_pkts=sum(1 for p in fwd_pkts if p.payload_length > 0),
        # la fel de redundant ca fwd_seg_size_avg de mai sus - interpretare
        # proprie (minimul lungimii de pachet observate pe directia forward)
        fwd_seg_size_min=fwd_pkt_len_min,
        active_mean=active_mean,
        active_std=active_std,
        active_max=active_max,
        active_min=active_min,
        idle_mean=idle_mean,
        idle_std=idle_std,
        idle_max=idle_max,
        idle_min=idle_min,
    )


def to_feature_frame(records: list[CicFlowFeatures]) -> pd.DataFrame:
    """exclude campurile de identificare (src_ip/dst_ip/src_port) - spre
    deosebire de nsl_kdd_style.py, `dst_port` si `protocol` RAMAN in
    DataFrame, pentru ca sunt features reale in schema CICFlowMeter
    originala, nu doar identificare"""
    rows = []
    for r in records:
        row = asdict(r)
        del row["src_ip"]
        del row["dst_ip"]
        del row["src_port"]
        rows.append(row)
    return pd.DataFrame(rows)
