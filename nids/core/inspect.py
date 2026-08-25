from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from nids.core.ml_combination import Agreement, combine_predictions, describe_agreement
from nids.ml.expert.model import ExpertModel, FeatureContribution
from nids.ml.expert.predict import explain_connection, predict_connections
from nids.ml.features.nsl_kdd_style import NslKddStyleFeatures
from nids.ml.local.learning import CategoricalRarity, FeatureDeviation, LocalModelManager


@dataclass
class ConnectionAssessment:
    record: NslKddStyleFeatures
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


def assess_connection(
    record: NslKddStyleFeatures,
    expert: ExpertModel | None,
    local_manager: LocalModelManager | None,
) -> ConnectionAssessment:
    """analiza completa, la cerere, a UNEI conexiuni - indiferent daca a
    fost sau nu semnalata automat. spre deosebire de fluxul normal
    (care raporteaza doar ce e interesant), aici userul vrea sa vada
    intotdeauna ceva, chiar daca raspunsul e "totul e normal" """
    expert_pred: int | None = None
    expert_features: list[FeatureContribution] = []
    if expert is not None:
        expert_pred = predict_connections(expert, [record])[0]
        expert_features = explain_connection(expert, record)

    local_pred: int | None = None
    local_score: float | None = None
    local_deviations: list[FeatureDeviation] = []
    local_rarities: list[CategoricalRarity] = []
    local_is_learning = True
    if local_manager is not None:
        local_is_learning = local_manager.is_learning
        # comparatia cu bufferul e utila chiar si in modul invatare (date
        # partiale, dar tot spun ceva) - doar predictia formala are
        # nevoie de model antrenat
        local_deviations = local_manager.explain(record)
        local_rarities = local_manager.explain_categorical(record)
        if not local_is_learning:
            local_pred = local_manager.predict_only(record)
            local_score = local_manager.anomaly_score(record)

    agreement: Agreement | None = None
    event_type = "evaluare incompleta"
    explanation = "modelul expert nu e disponibil - nu se poate face o evaluare completa"
    if expert_pred is not None:
        agreement = combine_predictions(expert_pred, None if local_is_learning else local_pred)
        described = describe_agreement(agreement, record.dst_ip, expert_pred)
        event_type = described.event_type
        explanation = described.description

    return ConnectionAssessment(
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


def assessment_to_json(assessment: ConnectionAssessment) -> str:
    """"poza" completa a analizei, salvata o singura data cand evenimentul
    e creat - permite redeschiderea aceluiasi ConnectionInspectorDialog
    mai tarziu (alta sesiune, alta zi), cand pachetele brute originale nu
    mai exista deja (traiesc doar in memorie cat ruleaza monitorizarea).
    nu salveaza `agreement` (enum, nefolosit de dialog) - restul e complet"""
    payload = {
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
    # predictiile/scorurile vin din sklearn/numpy (int64, float32...), pe
    # care json nu le stie serializa direct - .item() le converteste la
    # tipul nativ python echivalent, fara sa adaugam numpy ca dependinta aici
    return json.dumps(payload, default=_json_default)


def _json_default(value):
    if hasattr(value, "item"):
        return value.item()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def assessment_from_json(raw: str) -> ConnectionAssessment:
    payload = json.loads(raw)
    return ConnectionAssessment(
        record=NslKddStyleFeatures(**payload["record"]),
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


def format_explanation_snippet(
    expert_features: list[FeatureContribution],
    local_deviations: list[FeatureDeviation],
    local_rarities: list[CategoricalRarity] | None = None,
    top_n: int = 3,
) -> str:
    """rezumat scurt, pe intelesul omului, al motivelor fiecarui model -
    facut sa intre direct in descrierea unui Event (Loguri), nu doar in
    dialogul de inspectie la cerere. userul a cerut explicit sa vada "ce
    vede modelul local fata de cel expert" direct in jurnal, mai ales
    cand modelul local incepe sa semnaleze des"""
    parts = []

    if expert_features:
        top_expert = ", ".join(
            f"{c.feature}={c.value} ({c.importance:.0%})" for c in expert_features[:top_n]
        )
        parts.append(f"model expert vede: {top_expert}")

    local_bits = []

    # doar deviatiile notabile - altfel e zgomot, aproape orice valoare
    # are un z-score nenul
    notable = [d for d in local_deviations if abs(d.z_score) >= 1.0][:top_n]
    local_bits.extend(
        f"{d.feature}={d.value:g} (normal ~{d.baseline_mean:.2g}, z={d.z_score:+.1f})"
        for d in notable
    )

    # combinatii categorice rare (protocol/serviciu/flag) - Isolation
    # Forest le vede, dar deviatiile numerice de mai sus nu le arata deloc
    if local_rarities:
        rare = [r for r in local_rarities if r.frequency < 0.1][: max(top_n - len(local_bits), 0)]
        local_bits.extend(f"{r.feature}={r.value} (doar {r.frequency:.0%} din trafic)" for r in rare)

    if local_bits:
        parts.append(f"model local vede: {', '.join(local_bits)}")

    return " | ".join(parts)
