import random

from nids.ml.local.model import LocalModel
from tests.factories import make_record


def _normal_records(n: int = 60) -> list:
    rng = random.Random(42)
    return [
        make_record(
            src_bytes=200 + rng.randint(-20, 20),
            dst_bytes=1000 + rng.randint(-100, 100),
            duration=0.1 + rng.random() * 0.05,
        )
        for _ in range(n)
    ]


def test_local_model_train_predict_round_trip(tmp_path):
    records = _normal_records()
    model = LocalModel.train(records)

    predictions = model.predict(records)
    assert len(predictions) == len(records)
    assert set(predictions).issubset({0, 1})

    path = tmp_path / "local.joblib"
    model.save(path)
    loaded = LocalModel.load(path)
    assert loaded.predict(records) == predictions


def test_local_model_flags_extreme_outlier():
    model = LocalModel.train(_normal_records(60))

    outlier = make_record(
        src_bytes=500_000,
        dst_bytes=0,
        count=200,
        srv_count=200,
        service="private",
        flag="S0",
        serror_rate=1.0,
    )

    assert model.predict([outlier])[0] == 1


def test_local_model_predict_empty_input():
    model = LocalModel.train(_normal_records())

    assert model.predict([]) == []


def test_local_model_train_accepts_custom_contamination():
    model = LocalModel.train(_normal_records(), contamination=0.2)

    assert model._model.contamination == 0.2


def test_local_model_train_defaults_to_auto_contamination():
    model = LocalModel.train(_normal_records())

    assert model._model.contamination == "auto"


def test_anomaly_score_is_higher_for_clear_outlier():
    model = LocalModel.train(_normal_records(60))
    normal = make_record(src_bytes=200, dst_bytes=1000)
    outlier = make_record(
        src_bytes=500_000,
        dst_bytes=0,
        count=200,
        srv_count=200,
        service="private",
        flag="S0",
        serror_rate=1.0,
    )

    scores = model.anomaly_score([normal, outlier])

    assert scores[1] > scores[0]


def test_anomaly_score_empty_input():
    model = LocalModel.train(_normal_records())

    assert model.anomaly_score([]) == []


def test_local_model_train_accepts_custom_n_estimators():
    model = LocalModel.train(_normal_records(), n_estimators=50)

    assert model._model.n_estimators == 50


def test_local_model_train_defaults_to_100_estimators():
    model = LocalModel.train(_normal_records())

    assert model._model.n_estimators == 100


def test_anomaly_score_returns_native_floats():
    model = LocalModel.train(_normal_records())

    scores = model.anomaly_score([make_record()])

    assert isinstance(scores[0], float)
