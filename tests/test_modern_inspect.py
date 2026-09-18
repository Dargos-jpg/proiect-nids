import json

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from nids.ml.modern.inspect import assess_modern, modern_assessment_from_json, modern_assessment_to_json
from nids.ml.modern.learning import ModernLocalModelManager
from nids.ml.modern.model import ModernExpertModel
from tests.factories import make_cicflow_record


def _tiny_model() -> ModernExpertModel:
    x_train = pd.DataFrame({"flow_duration": [10, 5000], "totlen_fwd_pkts": [10, 6000]})
    model = RandomForestClassifier(n_estimators=5, random_state=42)
    model.fit(x_train, [0, 1])
    return ModernExpertModel(model, list(x_train.columns))


def test_assess_without_expert_model():
    result = assess_modern(make_cicflow_record(), expert=None, local_manager=None)

    assert result.expert_prediction is None
    assert result.expert_top_features == []
    assert result.agreement is None
    assert "nu e disponibil" in result.explanation


def test_assess_without_local_manager():
    result = assess_modern(make_cicflow_record(), expert=_tiny_model(), local_manager=None)

    assert result.expert_prediction in (0, 1)
    assert result.local_prediction is None
    assert result.local_is_learning is True
    assert result.agreement is not None


def test_assess_with_local_manager_still_learning():
    local_manager = ModernLocalModelManager(min_training_samples=1000)
    local_manager.process(make_cicflow_record())

    result = assess_modern(make_cicflow_record(), expert=_tiny_model(), local_manager=local_manager)

    assert result.local_is_learning is True
    assert result.local_prediction is None
    assert result.local_deviations != []


def test_assess_with_active_local_manager_returns_full_picture():
    local_manager = ModernLocalModelManager(min_training_samples=5)
    for _ in range(5):
        local_manager.process(make_cicflow_record(flow_duration=100))

    result = assess_modern(
        make_cicflow_record(flow_duration=100), expert=_tiny_model(), local_manager=local_manager
    )

    assert result.local_is_learning is False
    assert result.local_prediction in (0, 1)
    assert result.local_anomaly_score is not None
    assert isinstance(result.local_anomaly_score, float)
    assert result.expert_top_features != []
    assert result.explanation != ""


def test_assess_does_not_mutate_local_manager_state():
    local_manager = ModernLocalModelManager(min_training_samples=5)
    for _ in range(5):
        local_manager.process(make_cicflow_record(flow_duration=100))
    collected_before = local_manager.samples_collected

    assess_modern(
        make_cicflow_record(flow_duration=100), expert=_tiny_model(), local_manager=local_manager
    )

    assert local_manager.samples_collected == collected_before


def test_assess_modern_keeps_the_original_record():
    record = make_cicflow_record(src_ip="192.168.1.5")

    assessment = assess_modern(record, expert=None, local_manager=None)

    assert assessment.record is record


# --- persistare (assessment_json) - vezi ModernLiveHybridAnalyzer.evaluate() ---


def test_json_round_trip_preserves_all_fields():
    local_manager = ModernLocalModelManager(min_training_samples=5)
    for _ in range(5):
        local_manager.process(make_cicflow_record(flow_duration=100))
    assessment = assess_modern(
        make_cicflow_record(flow_duration=100), expert=_tiny_model(), local_manager=local_manager
    )

    restored = modern_assessment_from_json(modern_assessment_to_json(assessment))

    assert restored.record == assessment.record
    assert restored.expert_prediction == assessment.expert_prediction
    assert restored.expert_top_features == assessment.expert_top_features
    assert restored.local_prediction == assessment.local_prediction
    assert restored.local_is_learning == assessment.local_is_learning
    assert restored.local_anomaly_score == assessment.local_anomaly_score
    assert restored.local_deviations == assessment.local_deviations
    assert restored.local_categorical_rarities == assessment.local_categorical_rarities
    assert restored.event_type == assessment.event_type
    assert restored.explanation == assessment.explanation
    assert restored.agreement is None  # nu se salveaza, la fel ca la modelul vechi


def test_json_payload_is_marked_with_modern_model_key():
    """disambiguare fata de blob-urile vechi (nids.core.inspect) -
    DashboardPanel._load_assessment_json foloseste aceasta cheie"""
    assessment = assess_modern(make_cicflow_record(), expert=None, local_manager=None)

    payload = json.loads(modern_assessment_to_json(assessment))

    assert payload["model"] == "modern"
