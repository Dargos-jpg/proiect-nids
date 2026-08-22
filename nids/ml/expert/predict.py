from __future__ import annotations

from nids.ml.expert.model import ExpertModel
from nids.ml.expert.nsl_kdd import encode_features
from nids.ml.features.nsl_kdd_style import NslKddStyleFeatures, to_feature_frame


def predict_connections(
    expert: ExpertModel, records: list[NslKddStyleFeatures]
) -> list[int]:
    """0 = normal, 1 = atac, per conexiune - leaga extractorul propriu de
    features (nids.ml.features.nsl_kdd_style) de modelul expert antrenat
    pe acelasi subset de 28 coloane NSL-KDD"""
    if not records:
        return []

    raw = to_feature_frame(records)
    encoded = encode_features(raw)
    return expert.predict(encoded)
