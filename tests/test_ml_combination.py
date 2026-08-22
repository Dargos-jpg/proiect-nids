from nids.core.event import Severity
from nids.core.ml_combination import Agreement, combine_predictions, event_for_agreement


def test_combine_both_attack():
    assert combine_predictions(1, 1) == Agreement.BOTH_ATTACK


def test_combine_both_normal():
    assert combine_predictions(0, 0) == Agreement.BOTH_NORMAL


def test_combine_expert_only():
    assert combine_predictions(1, 0) == Agreement.EXPERT_ONLY


def test_combine_local_only():
    assert combine_predictions(0, 1) == Agreement.LOCAL_ONLY


def test_combine_local_learning():
    assert combine_predictions(1, None) == Agreement.LOCAL_LEARNING
    assert combine_predictions(0, None) == Agreement.LOCAL_LEARNING


def test_event_both_normal_is_none():
    assert event_for_agreement(Agreement.BOTH_NORMAL, "1.1.1.1", "2.2.2.2", 0) is None


def test_event_both_attack_is_high_severity():
    event = event_for_agreement(Agreement.BOTH_ATTACK, "1.1.1.1", "2.2.2.2", 1)

    assert event is not None
    assert event.severity == Severity.HIGH
    assert event.source_ip == "1.1.1.1"


def test_event_local_only_is_high_severity():
    event = event_for_agreement(Agreement.LOCAL_ONLY, "1.1.1.1", "2.2.2.2", 0)

    assert event is not None
    assert event.severity == Severity.HIGH


def test_event_expert_only_is_medium_severity():
    event = event_for_agreement(Agreement.EXPERT_ONLY, "1.1.1.1", "2.2.2.2", 1)

    assert event is not None
    assert event.severity == Severity.MEDIUM


def test_event_local_learning_with_expert_attack():
    event = event_for_agreement(Agreement.LOCAL_LEARNING, "1.1.1.1", "2.2.2.2", 1)

    assert event is not None
    assert event.severity == Severity.MEDIUM


def test_event_local_learning_with_expert_normal_is_none():
    assert event_for_agreement(Agreement.LOCAL_LEARNING, "1.1.1.1", "2.2.2.2", 0) is None
