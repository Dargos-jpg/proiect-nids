from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from nids.ml.expert.nsl_kdd import CATEGORICAL_COLUMNS

DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "data"
    / "models"
    / "expert_random_forest.joblib"
)


@dataclass
class FeatureContribution:
    feature: str
    value: str
    importance: float


def _base_feature_name(column: str) -> str:
    """coloanele categorice sunt one-hot ("service_http", "flag_SF") -
    grupeaza-le inapoi la numele original al feature-ului, ca explicatia
    sa fie pe intelesul omului, nu pe numele intern al coloanei encodate"""
    for category in CATEGORICAL_COLUMNS:
        if column.startswith(category + "_"):
            return category
    return column


class ExpertModel:
    """model pre-antrenat pe NSL-KDD - asteapta features in schema
    NSL-KDD (vezi nsl_kdd.py), NU in schema FlowFeatures din
    nids.ml.features.flow. legarea celor doua e un pas separat, inca
    nefacut - vezi NOTES.md"""

    def __init__(self, model: RandomForestClassifier, feature_columns: list[str]) -> None:
        self._model = model
        self._feature_columns = feature_columns

    @classmethod
    def load(cls, path: Path = DEFAULT_MODEL_PATH) -> ExpertModel:
        payload = joblib.load(path)
        return cls(payload["model"], payload["feature_columns"])

    def save(self, path: Path = DEFAULT_MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "feature_columns": self._feature_columns}, path)

    def predict(self, features: pd.DataFrame) -> list[int]:
        aligned = features.reindex(columns=self._feature_columns, fill_value=0)
        return list(self._model.predict(aligned))

    def explain(
        self, encoded: pd.DataFrame, raw_values: dict, top_n: int = 8
    ) -> list[FeatureContribution]:
        """cele mai importante features pentru acest model, cu valoarea
        lor pentru conexiunea data. importanta e GLOBALA (feature_importances_
        din Random Forest, calculata o data la antrenare), nu specifica
        acestei conexiuni - o aproximare rezonabila, nu o explicatie
        exacta gen SHAP (care ar cere o dependinta noua, nejustificata
        pentru scopul proiectului)"""
        importances = self._model.feature_importances_
        grouped: dict[str, float] = {}
        for col, imp in zip(self._feature_columns, importances):
            base = _base_feature_name(col)
            grouped[base] = grouped.get(base, 0.0) + float(imp)

        contributions = [
            FeatureContribution(feature=name, value=str(raw_values.get(name, "?")), importance=imp)
            for name, imp in grouped.items()
        ]
        contributions.sort(key=lambda c: c.importance, reverse=True)
        return contributions[:top_n]
