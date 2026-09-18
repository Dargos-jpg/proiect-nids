from __future__ import annotations

from nids.ml.features.cicflow_style import CicFlowFeatures, to_feature_frame
from nids.ml.modern.dataset import encode_features
from nids.ml.modern.model import FeatureContribution, ModernExpertModel


def predict_flows(expert: ModernExpertModel, records: list[CicFlowFeatures]) -> list[int]:
    """0 = normal, 1 = atac, per flux - vezi nids.ml.expert.predict, acelasi
    principiu, schema si model complet separate"""
    if not records:
        return []

    raw = to_feature_frame(records)
    encoded = encode_features(raw)
    return expert.predict(encoded)


def explain_flow(
    expert: ModernExpertModel, record: CicFlowFeatures, top_n: int = 8
) -> list[FeatureContribution]:
    raw = to_feature_frame([record])
    encoded = encode_features(raw)
    return expert.explain(encoded, raw.iloc[0].to_dict(), top_n=top_n)
