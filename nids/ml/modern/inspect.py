from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from nids.core.ml_combination import Agreement, combine_predictions, describe_agreement
from nids.ml.features.cicflow_style import CicFlowFeatures
from nids.ml.modern.learning import CategoricalRarity, FeatureDeviation, ModernLocalModelManager
from nids.ml.modern.model import FeatureContribution, ModernExpertModel
from nids.ml.modern.predict import explain_flow, predict_flows


@dataclass
class ModernAssessment:
    """echivalentul lui nids.core.inspect.ConnectionAssessment, dar pentru
    modelul expert+local MODERN (CSE-CIC-IDS2018) - aceeasi forma exacta,
    refolosind Agreement/combine_predictions/describe_agreement NESCHIMBATE
    (verificat: schema-agnostice, lucreaza doar cu predictii 0/1 si
    scoruri) - vezi DATASET-COMPARISON.md"""

    record: CicFlowFeatures
    expert_prediction: int | None
    expert_top_features: list[FeatureContribution]
    local_prediction: int | None
    local_is_learning: bool
    local_anomaly_score: float | None
    local_deviations: list[FeatureDeviation]
    local_categorical_rarities: list[CategoricalRarity]
    agreement: Agreement | None
    event_type: str
    explanation: str


def assess_modern(
    record: CicFlowFeatures,
    expert: ModernExpertModel | None,
    local_manager: ModernLocalModelManager | None,
) -> ModernAssessment:
    """vezi nids.core.inspect.assess_connection() - acelasi principiu
    exact, doar pe schema/modelele moderne"""
    expert_pred: int | None = None
    expert_features: list[FeatureContribution] = []
    if expert is not None:
        expert_pred = predict_flows(expert, [record])[0]
        expert_features = explain_flow(expert, record)

    local_pred: int | None = None
    local_score: float | None = None
    local_deviations: list[FeatureDeviation] = []
    local_rarities: list[CategoricalRarity] = []
    local_is_learning = True
    if local_manager is not None:
        local_is_learning = local_manager.is_learning
        local_deviations = local_manager.explain(record)
        local_rarities = local_manager.explain_categorical(record)
        if not local_is_learning:
            local_pred = local_manager.predict_only(record)
            local_score = local_manager.anomaly_score(record)

    agreement: Agreement | None = None
    event_type = "evaluare incompleta"
    explanation = "modelul expert modern nu e disponibil - nu se poate face o evaluare completa"
    if expert_pred is not None:
        agreement = combine_predictions(expert_pred, None if local_is_learning else local_pred)
        described = describe_agreement(agreement, record.dst_ip, expert_pred)
        event_type = described.event_type
        explanation = described.description

    return ModernAssessment(
        record=record,
        expert_prediction=expert_pred,
        expert_top_features=expert_features,
        local_prediction=local_pred,
        local_is_learning=local_is_learning,
        local_anomaly_score=local_score,
        local_deviations=local_deviations,
        local_categorical_rarities=local_rarities,
        agreement=agreement,
        event_type=event_type,
        explanation=explanation,
    )


def modern_assessment_to_json(assessment: ModernAssessment) -> str:
    """vezi nids.core.inspect.assessment_to_json - acelasi principiu (o
    "poza" completa, salvata o singura data la crearea evenimentului), doar
    pe schema moderna. de la Faza 6 (DATASET-COMPARISON.md), modelul modern
    e principalul care mai salveaza assessment_json pentru evenimente live
    - "model": "modern" permite disambiguarea la citire (vezi
    DashboardPanel._load_assessment_json)"""
    payload = {
        "model": "modern",
        "record": asdict(assessment.record),
        "expert_prediction": assessment.expert_prediction,
        "expert_top_features": [asdict(f) for f in assessment.expert_top_features],
        "local_prediction": assessment.local_prediction,
        "local_is_learning": assessment.local_is_learning,
        "local_anomaly_score": assessment.local_anomaly_score,
        "local_deviations": [asdict(d) for d in assessment.local_deviations],
        "local_categorical_rarities": [asdict(r) for r in assessment.local_categorical_rarities],
        "event_type": assessment.event_type,
        "explanation": assessment.explanation,
    }
    return json.dumps(payload, default=_json_default)


def _json_default(value):
    if hasattr(value, "item"):
        return value.item()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def modern_assessment_from_json(raw: str) -> ModernAssessment:
    payload = json.loads(raw)
    return ModernAssessment(
        record=CicFlowFeatures(**payload["record"]),
        expert_prediction=payload["expert_prediction"],
        expert_top_features=[FeatureContribution(**f) for f in payload["expert_top_features"]],
        local_prediction=payload["local_prediction"],
        local_is_learning=payload["local_is_learning"],
        local_anomaly_score=payload.get("local_anomaly_score"),
        local_deviations=[FeatureDeviation(**d) for d in payload["local_deviations"]],
        local_categorical_rarities=[
            CategoricalRarity(**r) for r in payload["local_categorical_rarities"]
        ],
        agreement=None,
        event_type=payload["event_type"],
        explanation=payload["explanation"],
    )
