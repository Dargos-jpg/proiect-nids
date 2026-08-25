import pytest

from nids.ml.local.learning import LocalModelManager
from tests.factories import make_record


def test_stays_in_learning_mode_until_enough_samples():
    manager = LocalModelManager(min_training_samples=5)

    results = [manager.process(make_record()) for _ in range(4)]

    assert all(r is None for r in results)
    assert manager.is_learning is True
    assert manager.samples_collected == 4


def test_switches_to_active_mode_after_enough_samples():
    manager = LocalModelManager(min_training_samples=5)

    for _ in range(4):
        manager.process(make_record())
    result = manager.process(make_record())

    assert result in (0, 1)
    assert manager.is_learning is False
    # bufferul NU se goleste dupa antrenare - ramane fereastra glisanta
    # pentru reantrenari ulterioare, nu se pierde ce s-a colectat
    assert manager.samples_collected == 5


def test_predicts_after_training():
    manager = LocalModelManager(min_training_samples=10)

    for _ in range(10):
        manager.process(make_record())

    next_result = manager.process(make_record())

    assert next_result in (0, 1)
    assert manager.is_learning is False


def test_buffer_is_a_sliding_window_capped_at_max_size():
    manager = LocalModelManager(min_training_samples=5, max_buffer_size=10)

    for _ in range(25):
        manager.process(make_record())

    assert manager.samples_collected == 10


def test_retrains_periodically_after_becoming_active():
    manager = LocalModelManager(min_training_samples=5, retrain_every=3)

    for _ in range(5):
        manager.process(make_record())
    model_after_training = manager._model

    for _ in range(3):
        manager.process(make_record())

    assert manager._model is not model_after_training


def test_retrain_uses_configured_contamination():
    manager = LocalModelManager(min_training_samples=5, contamination=0.25)

    for _ in range(5):
        manager.process(make_record())

    assert manager._model._model.contamination == 0.25


def test_retrain_defaults_to_auto_contamination():
    manager = LocalModelManager(min_training_samples=5)

    for _ in range(5):
        manager.process(make_record())

    assert manager._model._model.contamination == "auto"


def test_save_before_training_raises():
    manager = LocalModelManager(min_training_samples=10)

    with pytest.raises(RuntimeError):
        manager.save()


def test_save_after_training_writes_file(tmp_path):
    manager = LocalModelManager(min_training_samples=5)
    for _ in range(5):
        manager.process(make_record())

    path = tmp_path / "local.joblib"
    manager.save(path)

    assert path.exists()


def test_load_restores_model_and_buffer(tmp_path):
    path = tmp_path / "local.joblib"
    original = LocalModelManager(min_training_samples=5)
    for _ in range(5):
        original.process(make_record())
    original.save(path)

    restored = LocalModelManager.load(path)

    assert restored.is_learning is False
    assert restored.samples_collected == 5
    # reia direct de unde a ramas - nu mai trece prin invatare
    assert restored.process(make_record()) in (0, 1)


def test_load_or_new_falls_back_when_nothing_saved(tmp_path):
    manager = LocalModelManager.load_or_new(tmp_path / "nu-exista.joblib", min_training_samples=5)

    assert manager.is_learning is True
    assert manager.samples_collected == 0


def test_predict_only_returns_none_while_learning():
    manager = LocalModelManager(min_training_samples=5)
    manager.process(make_record())

    assert manager.predict_only(make_record()) is None


def test_predict_only_does_not_mutate_buffer():
    manager = LocalModelManager(min_training_samples=5)
    for _ in range(5):
        manager.process(make_record())
    collected_before = manager.samples_collected

    manager.predict_only(make_record())

    assert manager.samples_collected == collected_before


def test_explain_empty_before_any_data():
    manager = LocalModelManager(min_training_samples=5)

    assert manager.explain(make_record()) == []


def test_explain_flags_large_deviation():
    manager = LocalModelManager(min_training_samples=5)
    for src_bytes in (190, 195, 200, 205, 210, 195, 200, 205, 190, 210):
        manager.process(make_record(src_bytes=src_bytes))

    deviations = manager.explain(make_record(src_bytes=50_000))

    top = deviations[0]
    assert top.feature == "src_bytes"
    assert top.value == 50_000
    assert abs(top.z_score) > 10


def test_explain_categorical_empty_before_any_data():
    manager = LocalModelManager(min_training_samples=5)

    assert manager.explain_categorical(make_record()) == []


def test_explain_categorical_flags_rare_combination():
    manager = LocalModelManager(min_training_samples=5)
    for _ in range(9):
        manager.process(make_record(protocol_type="tcp", service="http", flag="SF"))
    manager.process(make_record(protocol_type="tcp", service="http", flag="SF"))

    rarities = manager.explain_categorical(
        make_record(protocol_type="udp", service="other", flag="SF")
    )

    by_feature = {r.feature: r for r in rarities}
    assert by_feature["protocol_type"].frequency == 0.0
    assert by_feature["service"].frequency == 0.0
    assert by_feature["flag"].frequency == 1.0  # SF e in tot bufferul


def test_explain_categorical_sorted_rarest_first():
    manager = LocalModelManager(min_training_samples=3)
    manager.process(make_record(protocol_type="tcp", service="http", flag="SF"))
    manager.process(make_record(protocol_type="tcp", service="http", flag="S0"))
    manager.process(make_record(protocol_type="tcp", service="http", flag="SF"))

    rarities = manager.explain_categorical(
        make_record(protocol_type="tcp", service="http", flag="S0")
    )

    assert rarities[0].feature == "flag"
    assert rarities[0].frequency < rarities[-1].frequency
