from nids.core.event import Severity
from nids.core.ml_combination import (
    Agreement,
    combine_predictions,
    describe_agreement,
    event_for_agreement,
)


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


def test_describe_agreement_both_normal_has_text_but_no_severity():
    described = describe_agreement(Agreement.BOTH_NORMAL, "2.2.2.2", 0)

    assert described.severity is None
    assert "normal" in described.description


def test_describe_agreement_local_learning_expert_normal_has_text_but_no_severity():
    described = describe_agreement(Agreement.LOCAL_LEARNING, "2.2.2.2", 0)

    assert described.severity is None
    assert "invatare" in described.description


def test_strict_mode_suppresses_expert_only():
    assert event_for_agreement(Agreement.EXPERT_ONLY, "1.1.1.1", "2.2.2.2", 1, strict=True) is None


def test_strict_mode_suppresses_local_only():
    assert event_for_agreement(Agreement.LOCAL_ONLY, "1.1.1.1", "2.2.2.2", 0, strict=True) is None


def test_strict_mode_suppresses_local_learning():
    assert (
        event_for_agreement(Agreement.LOCAL_LEARNING, "1.1.1.1", "2.2.2.2", 1, strict=True) is None
    )


def test_strict_mode_keeps_both_attack():
    event = event_for_agreement(Agreement.BOTH_ATTACK, "1.1.1.1", "2.2.2.2", 1, strict=True)

    assert event is not None
    assert event.severity == Severity.HIGH


def test_non_strict_mode_unchanged_by_default():
    event = event_for_agreement(Agreement.EXPERT_ONLY, "1.1.1.1", "2.2.2.2", 1)

    assert event is not None


def test_describe_agreement_matches_event_for_agreement_text():
    for agreement, expert_pred in [
        (Agreement.BOTH_ATTACK, 1),
        (Agreement.LOCAL_ONLY, 0),
        (Agreement.EXPERT_ONLY, 1),
        (Agreement.LOCAL_LEARNING, 1),
    ]:
        described = describe_agreement(agreement, "2.2.2.2", expert_pred)
        event = event_for_agreement(agreement, "1.1.1.1", "2.2.2.2", expert_pred)

        assert event is not None
        assert event.description == described.description
        assert event.event_type == described.event_type
        assert event.severity == described.severity
