from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from nids.capture.pcap_reader import read_pcap
from nids.ml.expert.model import ExpertModel
from nids.ml.expert.nsl_kdd import FEATURE_COLUMNS, prepare_features
from nids.ml.expert.predict import explain_connection, predict_connections
from nids.ml.features.nsl_kdd_style import extract_nsl_kdd_style_features
from tests.factories import make_record

PCAP_PATH = Path(__file__).resolve().parent.parent / "data" / "raw" / "http.cap"
_KDD_COLUMNS = FEATURE_COLUMNS + ["label", "difficulty"]


def _tiny_expert_model() -> ExpertModel:
    def row(protocol_type, service, flag, label, **overrides):
        values = {name: 0 for name in FEATURE_COLUMNS}
        values.update(protocol_type=protocol_type, service=service, flag=flag)
        values.update(overrides)
        return [values[name] for name in FEATURE_COLUMNS] + [label, 20]

    train_df = pd.DataFrame(
        [
            row("tcp", "http", "SF", "normal", src_bytes=200, dst_bytes=2000, count=1),
            row("tcp", "private", "S0", "neptune", src_bytes=0, dst_bytes=0, count=50),
            row("tcp", "http", "SF", "normal", src_bytes=150, dst_bytes=1500, count=2),
            row("tcp", "private", "S0", "neptune", src_bytes=0, dst_bytes=0, count=80),
        ],
        columns=_KDD_COLUMNS,
    )

    x_train, y_train = prepare_features(train_df)
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(x_train, y_train)

    return ExpertModel(model, list(x_train.columns))


def test_predict_connections_on_real_pcap_returns_one_label_per_connection():
    expert = _tiny_expert_model()
    packets = read_pcap(str(PCAP_PATH))
    records = extract_nsl_kdd_style_features(packets)

    predictions = predict_connections(expert, records)

    assert len(predictions) == len(records)
    assert set(predictions).issubset({0, 1})


def test_predict_connections_on_empty_input():
    expert = _tiny_expert_model()

    assert predict_connections(expert, []) == []


def test_explain_connection_returns_features_with_values():
    expert = _tiny_expert_model()
    record = make_record(src_bytes=200, dst_bytes=2000, service="http", flag="SF")

    contributions = explain_connection(expert, record, top_n=5)

    assert len(contributions) <= 5
    assert len(contributions) > 0
    # sortate descrescator dupa importanta
    importances = [c.importance for c in contributions]
    assert importances == sorted(importances, reverse=True)
    # coloanele one-hot sunt grupate inapoi la numele original
    assert all(c.feature in FEATURE_COLUMNS for c in contributions)


def test_explain_connection_value_matches_record():
    expert = _tiny_expert_model()
    record = make_record(src_bytes=777)

    contributions = explain_connection(expert, record, top_n=28)

    src_bytes_contribution = next(c for c in contributions if c.feature == "src_bytes")
    assert src_bytes_contribution.value == "777"
