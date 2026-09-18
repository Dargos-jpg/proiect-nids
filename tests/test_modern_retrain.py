import pandas as pd

from nids.honeypot.listener import HoneypotHit
from nids.honeypot.training_data import hit_to_packets
from nids.ml.modern.dataset import COLUMN_RENAME_MAP
from nids.ml.modern.model import ModernExpertModel
from nids.ml.modern.retrain import _is_at_least_as_good, retrain_with_honeypot_data

_ORIGINAL_COLUMNS = list(COLUMN_RENAME_MAP.keys())  # include si "Label"


def _row(label: str, flow_duration: int = 0) -> dict:
    """o linie in formatul brut CICFlowMeter (nume originale de coloane) -
    doar Protocol/Flow Duration variaza, restul raman 0, suficient pentru
    un RandomForest jucarie in test"""
    row = {name: 0 for name in _ORIGINAL_COLUMNS}
    row["Protocol"] = 6  # tcp
    row["Flow Duration"] = flow_duration
    row["Label"] = label
    return row


def _write_dataset(path, rows: list[dict]) -> None:
    pd.DataFrame(rows).to_csv(path, index=False)


def _honeypot_packets(n: int) -> list:
    packets = []
    for i in range(n):
        hit = HoneypotHit(
            src_ip=f"10.0.0.{i}", src_port=40000 + i, dst_port=2222, received_preview="scan"
        )
        packets.extend(hit_to_packets(hit, timestamp=float(i)))
    return packets


def _dataset_paths(tmp_path):
    train_path = tmp_path / "train.csv"
    test_path = tmp_path / "test.csv"
    _write_dataset(
        train_path,
        [
            _row("Benign", 100),
            _row("Benign", 120),
            _row("Bot", 0),
            _row("Bot", 5),
        ],
    )
    _write_dataset(test_path, [_row("Benign", 110), _row("Bot", 2)])
    return train_path, test_path


def _save_valid_model(path, feature_columns=("flow_duration",)) -> None:
    from sklearn.ensemble import RandomForestClassifier

    model = RandomForestClassifier(n_estimators=5, random_state=0)
    model.fit(pd.DataFrame({"flow_duration": [0, 100, 5, 120]}), [1, 0, 1, 0])
    ModernExpertModel(model, list(feature_columns)).save(path)


# --- _is_at_least_as_good ---


def test_is_at_least_as_good_true_when_equal():
    assert _is_at_least_as_good(0.8, 0.8) is True


def test_is_at_least_as_good_false_when_regressed():
    assert _is_at_least_as_good(0.9, 0.7) is False


# --- retrain_with_honeypot_data ---


def test_retrain_produces_result_with_expected_sample_count(tmp_path):
    train_path, test_path = _dataset_paths(tmp_path)
    model_out = tmp_path / "modern_expert.joblib"

    result = retrain_with_honeypot_data(
        _honeypot_packets(3),
        train_path=train_path,
        test_path=test_path,
        model_out_path=model_out,
        n_estimators=5,
        min_samples_leaf=1,
    )

    assert result.honeypot_connections_used == 3
    assert 0.0 <= result.accuracy_before <= 1.0
    assert 0.0 <= result.accuracy_after <= 1.0


def test_retrain_saves_a_loadable_model(tmp_path):
    train_path, test_path = _dataset_paths(tmp_path)
    model_out = tmp_path / "modern_expert.joblib"

    retrain_with_honeypot_data(
        _honeypot_packets(3),
        train_path=train_path,
        test_path=test_path,
        model_out_path=model_out,
        n_estimators=5,
        min_samples_leaf=1,
    )

    loaded = ModernExpertModel.load(model_out)
    prediction = loaded.predict(pd.DataFrame({"flow_duration": [10]}))
    assert len(prediction) == 1


def test_retrain_without_previous_model_always_saves(tmp_path):
    train_path, test_path = _dataset_paths(tmp_path)
    model_out = tmp_path / "modern_expert.joblib"

    result = retrain_with_honeypot_data(
        _honeypot_packets(3),
        train_path=train_path,
        test_path=test_path,
        model_out_path=model_out,
        n_estimators=5,
        min_samples_leaf=1,
    )

    assert result.model_saved is True
    assert model_out.exists()


def test_retrain_backs_up_previous_model_before_overwriting(tmp_path, monkeypatch):
    train_path, test_path = _dataset_paths(tmp_path)
    model_out = tmp_path / "modern_expert.joblib"
    _save_valid_model(model_out)
    monkeypatch.setattr("nids.ml.modern.retrain._is_at_least_as_good", lambda before, after: True)

    result = retrain_with_honeypot_data(
        _honeypot_packets(3),
        train_path=train_path,
        test_path=test_path,
        model_out_path=model_out,
        n_estimators=5,
        min_samples_leaf=1,
    )

    backup = model_out.with_suffix(model_out.suffix + ".bak")
    assert result.model_saved is True
    assert backup.exists()


def test_retrain_does_not_overwrite_when_accuracy_regresses(tmp_path, monkeypatch):
    train_path, test_path = _dataset_paths(tmp_path)
    model_out = tmp_path / "modern_expert.joblib"
    _save_valid_model(model_out)
    original_bytes = model_out.read_bytes()
    monkeypatch.setattr("nids.ml.modern.retrain._is_at_least_as_good", lambda before, after: False)

    result = retrain_with_honeypot_data(
        _honeypot_packets(3),
        train_path=train_path,
        test_path=test_path,
        model_out_path=model_out,
        n_estimators=5,
        min_samples_leaf=1,
    )

    assert result.model_saved is False
    assert model_out.read_bytes() == original_bytes
    assert not model_out.with_suffix(model_out.suffix + ".bak").exists()


def test_retrain_does_not_create_backup_when_no_previous_model(tmp_path):
    train_path, test_path = _dataset_paths(tmp_path)
    model_out = tmp_path / "modern_expert.joblib"

    retrain_with_honeypot_data(
        _honeypot_packets(3),
        train_path=train_path,
        test_path=test_path,
        model_out_path=model_out,
        n_estimators=5,
        min_samples_leaf=1,
    )

    assert not model_out.with_suffix(model_out.suffix + ".bak").exists()
