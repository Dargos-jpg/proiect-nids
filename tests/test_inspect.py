import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from nids.core.inspect import (
    assess_connection,
    assessment_from_json,
    assessment_to_json,
    format_explanation_snippet,
)
from nids.ml.expert.model import ExpertModel, FeatureContribution
from nids.ml.expert.nsl_kdd import FEATURE_COLUMNS, prepare_features
from nids.ml.local.learning import CategoricalRarity, FeatureDeviation, LocalModelManager
from tests.factories import make_record

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


def test_assess_without_expert_model():
    result = assess_connection(make_record(), expert=None, local_manager=None)

    assert result.expert_prediction is None
    assert result.agreement is None
    assert "nu e disponibil" in result.explanation


def test_assess_without_local_manager():
    expert = _tiny_expert_model()

    result = assess_connection(make_record(), expert=expert, local_manager=None)

    assert result.expert_prediction in (0, 1)
    assert result.local_prediction is None
    assert result.local_is_learning is True
    assert result.agreement is not None


def test_assess_with_local_manager_still_learning():
    expert = _tiny_expert_model()
    local_manager = LocalModelManager(min_training_samples=1000)
    local_manager.process(make_record())

    result = assess_connection(make_record(), expert=expert, local_manager=local_manager)

    assert result.local_is_learning is True
    assert result.local_prediction is None
    assert result.local_deviations != []


def test_assess_with_active_local_manager_returns_full_picture():
    expert = _tiny_expert_model()
    local_manager = LocalModelManager(min_training_samples=5)
    for _ in range(5):
        local_manager.process(make_record(src_bytes=200))

    result = assess_connection(
        make_record(src_bytes=200), expert=expert, local_manager=local_manager
    )

    assert result.local_is_learning is False
    assert result.local_prediction in (0, 1)
    assert result.local_anomaly_score is not None
    assert isinstance(result.local_anomaly_score, float)
    assert result.expert_top_features != []
    assert result.explanation != ""


def test_assess_with_learning_local_manager_has_no_anomaly_score():
    expert = _tiny_expert_model()
    local_manager = LocalModelManager(min_training_samples=1000)
    local_manager.process(make_record())

    result = assess_connection(make_record(), expert=expert, local_manager=local_manager)

    assert result.local_anomaly_score is None


def test_assess_does_not_mutate_local_manager_state():
    expert = _tiny_expert_model()
    local_manager = LocalModelManager(min_training_samples=5)
    for _ in range(5):
        local_manager.process(make_record(src_bytes=200))
    collected_before = local_manager.samples_collected

    assess_connection(make_record(src_bytes=200), expert=expert, local_manager=local_manager)

    assert local_manager.samples_collected == collected_before


def test_assessment_json_round_trip_preserves_everything():
    expert = _tiny_expert_model()
    local_manager = LocalModelManager(min_training_samples=5)
    for _ in range(5):
        local_manager.process(make_record(src_bytes=200))
    original = assess_connection(
        make_record(src_bytes=200), expert=expert, local_manager=local_manager
    )

    restored = assessment_from_json(assessment_to_json(original))

    assert restored.record == original.record
    assert restored.expert_prediction == original.expert_prediction
    assert restored.expert_top_features == original.expert_top_features
    assert restored.local_prediction == original.local_prediction
    assert restored.local_is_learning == original.local_is_learning
    assert restored.local_anomaly_score == original.local_anomaly_score
    assert restored.local_deviations == original.local_deviations
    assert restored.local_categorical_rarities == original.local_categorical_rarities
    assert restored.event_type == original.event_type
    assert restored.explanation == original.explanation


def test_assessment_from_json_handles_missing_score_key():
    """compatibilitate cu assessment_json salvat inainte de introducerea
    scorului continuu - fara cheia noua, nu trebuie sa arunce KeyError"""
    import json

    payload = json.loads(
        assessment_to_json(assess_connection(make_record(), expert=None, local_manager=None))
    )
    del payload["local_anomaly_score"]

    restored = assessment_from_json(json.dumps(payload))

    assert restored.local_anomaly_score is None


def test_assessment_json_round_trip_without_models():
    original = assess_connection(make_record(), expert=None, local_manager=None)

    restored = assessment_from_json(assessment_to_json(original))

    assert restored.expert_prediction is None
    assert restored.local_prediction is None
    assert restored.expert_top_features == []
    assert restored.explanation == original.explanation


def test_format_explanation_snippet_includes_both_models():
    expert_features = [
        FeatureContribution(feature="flag", value="S0", importance=0.4),
        FeatureContribution(feature="count", value="50", importance=0.3),
    ]
    local_deviations = [
        FeatureDeviation(
            feature="dst_bytes", value=0, baseline_mean=1400.0, baseline_std=200.0, z_score=-7.0
        )
    ]

    snippet = format_explanation_snippet(expert_features, local_deviations)

    assert "model expert vede:" in snippet
    assert "flag=S0 (40%)" in snippet
    assert "model local vede:" in snippet
    assert "dst_bytes=0" in snippet
    assert "z=-7.0" in snippet


def test_format_explanation_snippet_ignores_small_deviations():
    local_deviations = [
        FeatureDeviation(
            feature="count", value=1, baseline_mean=1.0, baseline_std=0.5, z_score=0.1
        )
    ]

    snippet = format_explanation_snippet([], local_deviations)

    assert snippet == ""


def test_format_explanation_snippet_empty_when_nothing_to_show():
    assert format_explanation_snippet([], []) == ""


def test_format_explanation_snippet_respects_top_n():
    expert_features = [
        FeatureContribution(feature=f"f{i}", value=str(i), importance=1.0 - i * 0.1)
        for i in range(10)
    ]

    snippet = format_explanation_snippet(expert_features, [], top_n=2)

    assert snippet.count("=") == 2
    assert "f2=" not in snippet


def test_format_explanation_snippet_includes_rare_categorical_combination():
    rarities = [
        CategoricalRarity(feature="protocol_type", value="udp", frequency=0.02),
        CategoricalRarity(feature="flag", value="SF", frequency=0.9),
    ]

    snippet = format_explanation_snippet([], [], local_rarities=rarities)

    assert "protocol_type=udp" in snippet
    assert "2%" in snippet
    assert "flag=SF" not in snippet  # 90% - nu e rar, nu trebuie sa apara


def test_format_explanation_snippet_ignores_common_categorical_values():
    rarities = [CategoricalRarity(feature="service", value="http", frequency=0.95)]

    snippet = format_explanation_snippet([], [], local_rarities=rarities)

    assert snippet == ""
