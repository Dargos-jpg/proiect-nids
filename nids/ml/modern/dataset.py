from __future__ import annotations

from pathlib import Path

import pandas as pd

# maparea explicita nume original CICFlowMeter -> numele folosite de
# nids.ml.features.cicflow_style.CicFlowFeatures (acelasi extractor
# folosit pe trafic capturat live/PCAP) - CRITICA pentru ca modelul sa
# functioneze corect pe trafic real: daca numele de coloane nu coincid
# exact, ExpertModel.predict() (reindex pe feature_columns, fill_value=0)
# ar completa tacut totul cu 0 in loc sa foloseasca valorile reale.
# exclude Timestamp (identificare, nu feature) si cele 6 coloane de
# "transfer in bloc" (vezi DATASET-COMPARISON.md - ies aproape mereu 0,
# excluse pe dovezi, la fel ca cele 13 coloane "content" din NSL-KDD)
COLUMN_RENAME_MAP = {
    "Dst Port": "dst_port",
    "Protocol": "protocol",
    "Flow Duration": "flow_duration",
    "Tot Fwd Pkts": "tot_fwd_pkts",
    "Tot Bwd Pkts": "tot_bwd_pkts",
    "TotLen Fwd Pkts": "totlen_fwd_pkts",
    "TotLen Bwd Pkts": "totlen_bwd_pkts",
    "Fwd Pkt Len Max": "fwd_pkt_len_max",
    "Fwd Pkt Len Min": "fwd_pkt_len_min",
    "Fwd Pkt Len Mean": "fwd_pkt_len_mean",
    "Fwd Pkt Len Std": "fwd_pkt_len_std",
    "Bwd Pkt Len Max": "bwd_pkt_len_max",
    "Bwd Pkt Len Min": "bwd_pkt_len_min",
    "Bwd Pkt Len Mean": "bwd_pkt_len_mean",
    "Bwd Pkt Len Std": "bwd_pkt_len_std",
    "Flow Byts/s": "flow_byts_per_s",
    "Flow Pkts/s": "flow_pkts_per_s",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Tot": "fwd_iat_tot",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Tot": "bwd_iat_tot",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "Fwd Header Len": "fwd_header_len",
    "Bwd Header Len": "bwd_header_len",
    "Fwd Pkts/s": "fwd_pkts_per_s",
    "Bwd Pkts/s": "bwd_pkts_per_s",
    "Pkt Len Min": "pkt_len_min",
    "Pkt Len Max": "pkt_len_max",
    "Pkt Len Mean": "pkt_len_mean",
    "Pkt Len Std": "pkt_len_std",
    "Pkt Len Var": "pkt_len_var",
    "FIN Flag Cnt": "fin_flag_cnt",
    "SYN Flag Cnt": "syn_flag_cnt",
    "RST Flag Cnt": "rst_flag_cnt",
    "PSH Flag Cnt": "psh_flag_cnt",
    "ACK Flag Cnt": "ack_flag_cnt",
    "URG Flag Cnt": "urg_flag_cnt",
    "CWE Flag Count": "cwe_flag_cnt",
    "ECE Flag Cnt": "ece_flag_cnt",
    "Down/Up Ratio": "down_up_ratio",
    "Pkt Size Avg": "pkt_size_avg",
    "Fwd Seg Size Avg": "fwd_seg_size_avg",
    "Bwd Seg Size Avg": "bwd_seg_size_avg",
    "Subflow Fwd Pkts": "subflow_fwd_pkts",
    "Subflow Fwd Byts": "subflow_fwd_byts",
    "Subflow Bwd Pkts": "subflow_bwd_pkts",
    "Subflow Bwd Byts": "subflow_bwd_byts",
    "Init Fwd Win Byts": "init_fwd_win_byts",
    "Init Bwd Win Byts": "init_bwd_win_byts",
    "Fwd Act Data Pkts": "fwd_act_data_pkts",
    "Fwd Seg Size Min": "fwd_seg_size_min",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
    "Label": "label",
}

FEATURE_COLUMNS = [v for k, v in COLUMN_RENAME_MAP.items() if k not in ("Label",)]
CATEGORICAL_COLUMNS = ["protocol"]

# numarul IANA de protocol e convertit in acelasi vocabular de string
# folosit de nids.capture.packet_meta.extract_meta() pe trafic REAL
# ("tcp"/"udp"/"icmp"), altfel encodarea one-hot ar avea categorii
# complet diferite intre antrenare (numere) si inferenta (string-uri).
# alte numere de protocol (rar intalnite) raman ca text al numarului -
# acelasi fallback ca in extract_meta()
_PROTOCOL_NAMES = {6: "tcp", 17: "udp", 1: "icmp"}


def _normalize_protocol(value) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value)
    return _PROTOCOL_NAMES.get(number, str(number))


def load_dataset(path: Path) -> pd.DataFrame:
    """citeste CSV-ul deja pregatit (esantionat + curatat -
    scripts/prepare_cse_cic_ids2018.py), redenumeste coloanele la schema
    proprie si normalizeaza "protocol" la acelasi vocabular ca traficul
    live capturat"""
    df = pd.read_csv(path)
    df = df.rename(columns=COLUMN_RENAME_MAP)
    df["protocol"] = df["protocol"].apply(_normalize_protocol)
    return df


def encode_features(
    df: pd.DataFrame, encoded_columns: list[str] | None = None
) -> pd.DataFrame:
    """encodeaza "protocol" (singura coloana categorica) one-hot - restul
    coloanelor sunt deja numerice. encoded_columns aliniaza alt set de date
    (ex: test) la coloanele vazute la antrenare, la fel ca in nsl_kdd.py"""
    x = pd.get_dummies(df[FEATURE_COLUMNS], columns=CATEGORICAL_COLUMNS)

    if encoded_columns is not None:
        x = x.reindex(columns=encoded_columns, fill_value=0)

    return x


def prepare_features(
    df: pd.DataFrame, encoded_columns: list[str] | None = None
) -> tuple[pd.DataFrame, pd.Series]:
    """ca encode_features, plus eticheta mapata la binar (0=Benign,
    1=atac) - clasificare binara, la fel ca la modelul vechi (NSL-KDD)"""
    y = (df["label"] != "Benign").astype(int)
    x = encode_features(df, encoded_columns)
    return x, y
