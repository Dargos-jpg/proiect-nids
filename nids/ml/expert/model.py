from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "data"
    / "models"
    / "expert_random_forest.joblib"
)


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
