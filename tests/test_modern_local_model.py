import random

from nids.ml.modern.local import ModernLocalModel
from tests.factories import make_cicflow_record


def _normal_records(n: int = 60) -> list:
    rng = random.Random(42)
    return [
        make_cicflow_record(
            flow_duration=100 + rng.randint(-20, 20),
            totlen_fwd_pkts=1000 + rng.randint(-100, 100),
        )
        for _ in range(n)
    ]


def _outlier():
    return make_cicflow_record(
        flow_duration=500_000,
        totlen_fwd_pkts=0,
        tot_fwd_pkts=200,
        tot_bwd_pkts=0,
        down_up_ratio=0.0,
        protocol="udp",
    )


def test_modern_local_model_train_predict_round_trip(tmp_path):
    records = _normal_records()
    model = ModernLocalModel.train(records)

    predictions = model.predict(records)
    assert len(predictions) == len(records)
    assert set(predictions).issubset({0, 1})

    path = tmp_path / "modern_local.joblib"
    model.save(path)
    loaded = ModernLocalModel.load(path)
    assert loaded.predict(records) == predictions


def test_modern_local_model_flags_extreme_outlier():
    model = ModernLocalModel.train(_normal_records(60))

    assert model.predict([_outlier()])[0] == 1


def test_modern_local_model_predict_empty_input():
    model = ModernLocalModel.train(_normal_records())

    assert model.predict([]) == []


def test_modern_local_model_train_accepts_custom_contamination():
    model = ModernLocalModel.train(_normal_records(), contamination=0.2)

    assert model._model.contamination == 0.2


def test_modern_local_model_train_defaults_to_auto_contamination():
    model = ModernLocalModel.train(_normal_records())

    assert model._model.contamination == "auto"


def test_modern_anomaly_score_is_higher_for_clear_outlier():
    model = ModernLocalModel.train(_normal_records(60))
    normal = make_cicflow_record(flow_duration=100, totlen_fwd_pkts=1000)

    scores = model.anomaly_score([normal, _outlier()])

    assert scores[1] > scores[0]


def test_modern_anomaly_score_empty_input():
    model = ModernLocalModel.train(_normal_records())

    assert model.anomaly_score([]) == []


def test_modern_local_model_train_accepts_custom_n_estimators():
    model = ModernLocalModel.train(_normal_records(), n_estimators=50)

    assert model._model.n_estimators == 50


def test_modern_local_model_train_defaults_to_100_estimators():
    model = ModernLocalModel.train(_normal_records())

    assert model._model.n_estimators == 100


def test_modern_anomaly_score_returns_native_floats():
    model = ModernLocalModel.train(_normal_records())

    scores = model.anomaly_score([make_cicflow_record()])

    assert isinstance(scores[0], float)
