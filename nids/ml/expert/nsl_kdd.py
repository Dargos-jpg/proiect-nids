from __future__ import annotations

from pathlib import Path

import pandas as pd

# toate cele 41 de coloane originale NSL-KDD - necesare ca sa citim
# corect fisierul (fiecare linie are 41 valori + label + difficulty, in
# aceasta ordine), chiar daca antrenam modelul doar pe un subset (vezi
# FEATURE_COLUMNS mai jos)
ALL_FEATURE_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

# subsetul pe care chiar antrenam modelul: categoriile "basic" (9) +
# "traffic" (19) - exact ce poate produce nids/ml/features/nsl_kdd_style.py
# din pachete capturate. celelalte 13 ("content": num_failed_logins,
# root_shell, num_shells etc.) cer inspectia payload-ului aplicatiei -
# nu le putem deriva din trafic, mai ales criptat, deci nu intra in model
FEATURE_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]
CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]
_COLUMNS = ALL_FEATURE_COLUMNS + ["label", "difficulty"]


def load_dataset(path: Path) -> pd.DataFrame:
    return pd.read_csv(path, names=_COLUMNS)


def encode_features(
    df: pd.DataFrame, encoded_columns: list[str] | None = None
) -> pd.DataFrame:
    """encodeaza coloanele categorice (one-hot) din FEATURE_COLUMNS.

    encoded_columns: coloanele rezultate din encodarea setului de
    antrenare - alte seturi de date pot avea categorii diferite (ex. un
    serviciu care nu apare in train), reindex le aliniaza pe amandoua
    la acelasi set de coloane, completand cu 0 ce lipseste"""
    x = pd.get_dummies(df[FEATURE_COLUMNS], columns=CATEGORICAL_COLUMNS)

    if encoded_columns is not None:
        x = x.reindex(columns=encoded_columns, fill_value=0)

    return x


def prepare_features(
    df: pd.DataFrame, encoded_columns: list[str] | None = None
) -> tuple[pd.DataFrame, pd.Series]:
    """ca encode_features, plus eticheta mapata la binar (0=normal,
    1=atac) - clasificare binara, nu pe tip de atac. foloseste pentru
    antrenare/evaluare, unde ai eticheta; pentru predictie pe trafic
    propriu (fara eticheta) foloseste direct encode_features"""
    y = (df["label"] != "normal").astype(int)
    x = encode_features(df, encoded_columns)
    return x, y
