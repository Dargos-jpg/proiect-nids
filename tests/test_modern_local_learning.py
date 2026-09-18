import pytest

from nids.ml.modern.learning import ModernLocalModelManager
from tests.factories import make_cicflow_record


def test_stays_in_learning_mode_until_enough_samples():
    manager = ModernLocalModelManager(min_training_samples=5)

    results = [manager.process(make_cicflow_record()) for _ in range(4)]

    assert all(r is None for r in results)
    assert manager.is_learning is True
    assert manager.samples_collected == 4


def test_switches_to_active_mode_after_enough_samples():
    manager = ModernLocalModelManager(min_training_samples=5)

    for _ in range(4):
        manager.process(make_cicflow_record())
    result = manager.process(make_cicflow_record())

    assert result in (0, 1)
    assert manager.is_learning is False
    assert manager.samples_collected == 5


def test_predicts_after_training():
    manager = ModernLocalModelManager(min_training_samples=10)

    for _ in range(10):
        manager.process(make_cicflow_record())

    next_result = manager.process(make_cicflow_record())

    assert next_result in (0, 1)
    assert manager.is_learning is False


def test_buffer_is_a_sliding_window_capped_at_max_size():
    manager = ModernLocalModelManager(min_training_samples=5, max_buffer_size=10)

    for _ in range(25):
        manager.process(make_cicflow_record())

    assert manager.samples_collected == 10


def test_retrains_periodically_after_becoming_active():
    manager = ModernLocalModelManager(min_training_samples=5, retrain_every=3)

    for _ in range(5):
        manager.process(make_cicflow_record())
    model_after_training = manager._model

    for _ in range(3):
        manager.process(make_cicflow_record())

    assert manager._model is not model_after_training


def test_retrain_uses_configured_contamination():
    manager = ModernLocalModelManager(min_training_samples=5, contamination=0.25)

    for _ in range(5):
        manager.process(make_cicflow_record())

    assert manager._model._model.contamination == 0.25


def test_retrain_defaults_to_auto_contamination():
    manager = ModernLocalModelManager(min_training_samples=5)

    for _ in range(5):
        manager.process(make_cicflow_record())

    assert manager._model._model.contamination == "auto"


def test_retrain_uses_configured_n_estimators():
    manager = ModernLocalModelManager(min_training_samples=5, n_estimators=30)

    for _ in range(5):
        manager.process(make_cicflow_record())

    assert manager._model._model.n_estimators == 30


def test_retrain_defaults_to_100_estimators():
    manager = ModernLocalModelManager(min_training_samples=5)

    for _ in range(5):
        manager.process(make_cicflow_record())

    assert manager._model._model.n_estimators == 100


def test_save_before_training_raises():
    manager = ModernLocalModelManager(min_training_samples=10)

    with pytest.raises(RuntimeError):
        manager.save()


def test_save_after_training_writes_file(tmp_path):
    manager = ModernLocalModelManager(min_training_samples=5)
    for _ in range(5):
        manager.process(make_cicflow_record())

    path = tmp_path / "modern_local.joblib"
    manager.save(path)

    assert path.exists()


def test_load_restores_model_and_buffer(tmp_path):
    path = tmp_path / "modern_local.joblib"
    original = ModernLocalModelManager(min_training_samples=5)
    for _ in range(5):
        original.process(make_cicflow_record())
    original.save(path)

    restored = ModernLocalModelManager.load(path)

    assert restored.is_learning is False
    assert restored.samples_collected == 5
    assert restored.process(make_cicflow_record()) in (0, 1)


def test_load_or_new_falls_back_when_nothing_saved(tmp_path):
    manager = ModernLocalModelManager.load_or_new(
        tmp_path / "nu-exista.joblib", min_training_samples=5
    )

    assert manager.is_learning is True
    assert manager.samples_collected == 0


def test_anomaly_score_returns_none_while_learning():
    manager = ModernLocalModelManager(min_training_samples=5)
    manager.process(make_cicflow_record())

    assert manager.anomaly_score(make_cicflow_record()) is None


def test_anomaly_score_returns_float_once_active():
    manager = ModernLocalModelManager(min_training_samples=5)
    for _ in range(5):
        manager.process(make_cicflow_record())

    assert isinstance(manager.anomaly_score(make_cicflow_record()), float)


def test_anomaly_score_does_not_mutate_buffer():
    manager = ModernLocalModelManager(min_training_samples=5)
    for _ in range(5):
        manager.process(make_cicflow_record())
    collected_before = manager.samples_collected

    manager.anomaly_score(make_cicflow_record())

    assert manager.samples_collected == collected_before


def test_anomaly_score_higher_for_outlier():
    manager = ModernLocalModelManager(min_training_samples=10)
    for duration in (90, 95, 100, 105, 110, 95, 100, 105, 90, 110):
        manager.process(make_cicflow_record(flow_duration=duration))

    normal_score = manager.anomaly_score(make_cicflow_record(flow_duration=100))
    outlier_score = manager.anomaly_score(
        make_cicflow_record(flow_duration=500_000, tot_fwd_pkts=200, down_up_ratio=0.0)
    )

    assert outlier_score > normal_score


def test_predict_only_returns_none_while_learning():
    manager = ModernLocalModelManager(min_training_samples=5)
    manager.process(make_cicflow_record())

    assert manager.predict_only(make_cicflow_record()) is None


def test_predict_only_does_not_mutate_buffer():
    manager = ModernLocalModelManager(min_training_samples=5)
    for _ in range(5):
        manager.process(make_cicflow_record())
    collected_before = manager.samples_collected

    manager.predict_only(make_cicflow_record())

    assert manager.samples_collected == collected_before


def test_explain_empty_before_any_data():
    manager = ModernLocalModelManager(min_training_samples=5)

    assert manager.explain(make_cicflow_record()) == []


def test_explain_flags_large_deviation():
    manager = ModernLocalModelManager(min_training_samples=5)
    for duration in (90, 95, 100, 105, 110, 95, 100, 105, 90, 110):
        manager.process(make_cicflow_record(flow_duration=duration))

    deviations = manager.explain(make_cicflow_record(flow_duration=50_000))

    top = deviations[0]
    assert top.feature == "flow_duration"
    assert top.value == 50_000
    assert abs(top.z_score) > 10


def test_explain_categorical_empty_before_any_data():
    manager = ModernLocalModelManager(min_training_samples=5)

    assert manager.explain_categorical(make_cicflow_record()) == []


def test_explain_categorical_flags_rare_combination():
    manager = ModernLocalModelManager(min_training_samples=5)
    for _ in range(10):
        manager.process(make_cicflow_record(protocol="tcp"))

    rarities = manager.explain_categorical(make_cicflow_record(protocol="udp"))

    by_feature = {r.feature: r for r in rarities}
    assert by_feature["protocol"].frequency == 0.0
