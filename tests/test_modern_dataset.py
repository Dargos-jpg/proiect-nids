import dataclasses

import pandas as pd

from nids.ml.features.cicflow_style import CicFlowFeatures
from nids.ml.modern.dataset import (
    FEATURE_COLUMNS,
    _normalize_protocol,
    encode_features,
    prepare_features,
)

_IDENTIFICATION_FIELDS = {"src_ip", "dst_ip", "src_port"}


def test_feature_columns_match_exactly_the_live_extractor_schema():
    """cea mai importanta verificare din tot modulul: daca FEATURE_COLUMNS
    (folosit la antrenare, din setul CSE-CIC-IDS2018) nu coincide EXACT cu
    campurile pe care extract_cicflow_features() le produce din trafic
    REAL capturat, modelul ar "vedea" coloane complet diferite la
    inferenta fata de antrenare - ExpertModel.predict() ar completa tacut
    totul cu 0 (reindex fill_value=0) in loc sa foloseasca valori reale,
    fara nicio eroare vizibila"""
    live_fields = {f.name for f in dataclasses.fields(CicFlowFeatures)} - _IDENTIFICATION_FIELDS

    assert set(FEATURE_COLUMNS) == live_fields


def test_feature_columns_have_no_duplicates():
    assert len(FEATURE_COLUMNS) == len(set(FEATURE_COLUMNS))


# --- normalizare protocol ---


def test_normalize_protocol_maps_known_iana_numbers():
    assert _normalize_protocol(6) == "tcp"
    assert _normalize_protocol(17) == "udp"
    assert _normalize_protocol(1) == "icmp"


def test_normalize_protocol_falls_back_to_number_string():
    assert _normalize_protocol(0) == "0"
    assert _normalize_protocol(2) == "2"


# --- encode/prepare ---


def _df(protocol="tcp", label="Benign", dst_port=80):
    row = {name: 0 for name in FEATURE_COLUMNS}
    row["protocol"] = protocol
    row["dst_port"] = dst_port
    row["label"] = label
    return pd.DataFrame([row])


def test_encode_features_one_hot_encodes_protocol():
    df = pd.concat([_df(protocol="tcp"), _df(protocol="udp")], ignore_index=True)

    x = encode_features(df)

    assert "protocol_tcp" in x.columns
    assert "protocol_udp" in x.columns
    assert "protocol" not in x.columns


def test_prepare_features_maps_label_to_binary():
    df = pd.concat(
        [_df(label="Benign"), _df(label="DDOS attack-HOIC"), _df(label="Bot")], ignore_index=True
    )

    x, y = prepare_features(df)

    assert list(y) == [0, 1, 1]
    assert "label" not in x.columns


def test_prepare_features_aligns_test_columns_to_train_columns():
    train_df = pd.concat([_df(protocol="tcp"), _df(protocol="udp")], ignore_index=True)
    test_df = _df(protocol="icmp")

    x_train, _ = prepare_features(train_df)
    x_test, _ = prepare_features(test_df, encoded_columns=list(x_train.columns))

    assert list(x_test.columns) == list(x_train.columns)
    assert "protocol_icmp" not in x_test.columns  # icmp nu a existat in train
