from __future__ import annotations

from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest

from nids.ml.features.cicflow_style import CicFlowFeatures, to_feature_frame
from nids.ml.modern.dataset import encode_features

DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "data"
    / "models"
    / "modern_local_isolation_forest.joblib"
)


class ModernLocalModel:
    """echivalentul lui nids.ml.local.model.LocalModel, dar pe schema
    CicFlowFeatures (72 features CICFlowMeter, CSE-CIC-IDS2018) - complet
    separat, nu imprumuta nimic din modelul local vechi (NSL-KDD).
    foloseste ACEEASI schema ca ModernExpertModel, ca sa poata fi comparate
    direct (dezacord intre modele)"""

    def __init__(self, model: IsolationForest, feature_columns: list[str]) -> None:
        self._model = model
        self._feature_columns = feature_columns

    @classmethod
    def train(
        cls,
        records: list[CicFlowFeatures],
        contamination: float | str = "auto",
        n_estimators: int = 100,
    ) -> ModernLocalModel:
        raw = to_feature_frame(records)
        encoded = encode_features(raw)
        model = IsolationForest(
            random_state=42, contamination=contamination, n_estimators=n_estimators
        )
        model.fit(encoded)
        return cls(model, list(encoded.columns))

    @classmethod
    def load(cls, path: Path = DEFAULT_MODEL_PATH) -> ModernLocalModel:
        payload = joblib.load(path)
        return cls(payload["model"], payload["feature_columns"])

    def save(self, path: Path = DEFAULT_MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "feature_columns": self._feature_columns}, path)

    def predict(self, records: list[CicFlowFeatures]) -> list[int]:
        """1 = anomalie, 0 = normal - vezi LocalModel.predict()"""
        if not records:
            return []
        raw = to_feature_frame(records)
        encoded = encode_features(raw, encoded_columns=self._feature_columns)
        raw_predictions = self._model.predict(encoded)
        return [1 if p == -1 else 0 for p in raw_predictions]

    def anomaly_score(self, records: list[CicFlowFeatures]) -> list[float]:
        """vezi LocalModel.anomaly_score() - aceeasi conventie (mai mare =
        mai anormal, inversul decision_function() din sklearn)"""
        if not records:
            return []
        raw = to_feature_frame(records)
        encoded = encode_features(raw, encoded_columns=self._feature_columns)
        return [-score for score in self._model.decision_function(encoded)]
