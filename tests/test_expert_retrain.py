import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from nids.honeypot.listener import HoneypotHit
from nids.honeypot.training_data import hit_to_packets
from nids.ml.expert.model import ExpertModel
from nids.ml.expert.nsl_kdd import ALL_FEATURE_COLUMNS
from nids.ml.expert.retrain import _is_at_least_as_good, retrain_with_honeypot_data

_N_COLS = len(ALL_FEATURE_COLUMNS)


def _row(label: str, src_bytes: int = 0) -> list:
    """o linie in formatul brut NSL-KDD (41 valori + label + difficulty) -
    doar protocol_type/service/flag/src_bytes variaza, restul raman 0,
    suficient pentru un RandomForest jucarie in test"""
    values = [0] * _N_COLS
    idx = ALL_FEATURE_COLUMNS.index
    values[idx("protocol_type")] = "tcp"
    values[idx("service")] = "http"
    values[idx("flag")] = "SF"
    values[idx("src_bytes")] = src_bytes
    return values + [label, 20]


def _write_dataset(path, rows: list[list]) -> None:
    pd.DataFrame(rows).to_csv(path, header=False, index=False)


def _honeypot_packets(n: int) -> list:
    packets = []
    for i in range(n):
        hit = HoneypotHit(
            src_ip=f"10.0.0.{i}", src_port=40000 + i, dst_port=2222, received_preview="scan"
        )
        packets.extend(hit_to_packets(hit, timestamp=float(i)))
    return packets


def _dataset_paths(tmp_path):
    train_path = tmp_path / "train.txt"
    test_path = tmp_path / "test.txt"
    _write_dataset(
        train_path,
        [_row("normal", 100), _row("normal", 120), _row("neptune", 0), _row("neptune", 5)],
    )
    _write_dataset(test_path, [_row("normal", 110), _row("neptune", 2)])
    return train_path, test_path


def _save_valid_model(path, feature_columns=("src_bytes",)) -> None:
    """model real, minimal, salvat la `path` - foloseste pentru a simula
    "exista deja un model activ", spre deosebire de octeti fictivi (care
    ar pica la ExpertModel.load(), apelat acum de retrain_with_honeypot_data
    pentru a evalua modelul CURENT, nu doar pentru a-i verifica existenta)"""
    model = RandomForestClassifier(n_estimators=5, random_state=0)
    model.fit(pd.DataFrame({"src_bytes": [0, 100, 5, 120]}), [1, 0, 1, 0])
    ExpertModel(model, list(feature_columns)).save(path)


# --- _is_at_least_as_good (functie pura, fara ML real) ---


def test_is_at_least_as_good_true_when_equal():
    assert _is_at_least_as_good(0.8, 0.8) is True


def test_is_at_least_as_good_true_when_improved():
    assert _is_at_least_as_good(0.7, 0.9) is True


def test_is_at_least_as_good_false_when_regressed():
    assert _is_at_least_as_good(0.9, 0.7) is False


# --- retrain_with_honeypot_data ---


def test_retrain_produces_result_with_expected_sample_count(tmp_path):
    train_path, test_path = _dataset_paths(tmp_path)
    model_out = tmp_path / "expert.joblib"

    result = retrain_with_honeypot_data(
        _honeypot_packets(3),
        train_path=train_path,
        test_path=test_path,
        model_out_path=model_out,
        n_estimators=5,
    )

    assert result.honeypot_connections_used == 3
    assert 0.0 <= result.accuracy_before <= 1.0
    assert 0.0 <= result.accuracy_after <= 1.0


def test_retrain_saves_a_loadable_model(tmp_path):
    train_path, test_path = _dataset_paths(tmp_path)
    model_out = tmp_path / "expert.joblib"

    retrain_with_honeypot_data(
        _honeypot_packets(3),
        train_path=train_path,
        test_path=test_path,
        model_out_path=model_out,
        n_estimators=5,
    )

    loaded = ExpertModel.load(model_out)
    prediction = loaded.predict(pd.DataFrame({"src_bytes": [10]}))
    assert len(prediction) == 1


def test_retrain_without_previous_model_always_saves(tmp_path):
    """nimic de "stricat" la prima reantrenare - se salveaza indiferent
    de cum iese comparatia cu baseline-ul informativ"""
    train_path, test_path = _dataset_paths(tmp_path)
    model_out = tmp_path / "expert.joblib"

    result = retrain_with_honeypot_data(
        _honeypot_packets(3),
        train_path=train_path,
        test_path=test_path,
        model_out_path=model_out,
        n_estimators=5,
    )

    assert result.model_saved is True
    assert model_out.exists()


def test_retrain_backs_up_previous_model_before_overwriting(tmp_path, monkeypatch):
    train_path, test_path = _dataset_paths(tmp_path)
    model_out = tmp_path / "expert.joblib"
    _save_valid_model(model_out)
    # fortam explicit "modelul nou e mai bun" - nu vrem sa depindem de cum
    # iese antrenarea reala pe date jucarie, doar sa testam ramura de backup
    monkeypatch.setattr(
        "nids.ml.expert.retrain._is_at_least_as_good", lambda before, after: True
    )

    result = retrain_with_honeypot_data(
        _honeypot_packets(3),
        train_path=train_path,
        test_path=test_path,
        model_out_path=model_out,
        n_estimators=5,
    )

    backup = model_out.with_suffix(model_out.suffix + ".bak")
    assert result.model_saved is True
    assert backup.exists()


def test_retrain_does_not_overwrite_when_accuracy_regresses(tmp_path, monkeypatch):
    """regresie pentru gaura de siguranta semnalata de user: daca noul
    model (NSL-KDD + honeypot) iese mai slab decat modelul activ pe
    KDDTest+, modelul activ NU trebuie inlocuit, chiar daca reantrenarea a
    rulat pana la capat"""
    train_path, test_path = _dataset_paths(tmp_path)
    model_out = tmp_path / "expert.joblib"
    _save_valid_model(model_out)
    original_bytes = model_out.read_bytes()
    monkeypatch.setattr(
        "nids.ml.expert.retrain._is_at_least_as_good", lambda before, after: False
    )

    result = retrain_with_honeypot_data(
        _honeypot_packets(3),
        train_path=train_path,
        test_path=test_path,
        model_out_path=model_out,
        n_estimators=5,
    )

    assert result.model_saved is False
    assert model_out.read_bytes() == original_bytes  # neschimbat
    assert not model_out.with_suffix(model_out.suffix + ".bak").exists()


def test_retrain_does_not_create_backup_when_no_previous_model(tmp_path):
    train_path, test_path = _dataset_paths(tmp_path)
    model_out = tmp_path / "expert.joblib"

    retrain_with_honeypot_data(
        _honeypot_packets(3),
        train_path=train_path,
        test_path=test_path,
        model_out_path=model_out,
        n_estimators=5,
    )

    assert not model_out.with_suffix(model_out.suffix + ".bak").exists()
