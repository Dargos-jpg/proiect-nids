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
    assert manager.samples_collected == 0


def test_predicts_after_training():
    manager = LocalModelManager(min_training_samples=10)

    for _ in range(10):
        manager.process(make_record())

    next_result = manager.process(make_record())

    assert next_result in (0, 1)
    assert manager.is_learning is False


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
