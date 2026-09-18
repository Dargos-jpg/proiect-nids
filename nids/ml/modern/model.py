from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from nids.ml.modern.dataset import CATEGORICAL_COLUMNS

DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "data"
    / "models"
    / "modern_expert_random_forest.joblib"
)


@dataclass
class FeatureContribution:
    feature: str
    value: str
    importance: float


def _base_feature_name(column: str) -> str:
    """coloanele categorice sunt one-hot ("protocol_tcp") - grupeaza-le
    inapoi la numele original al feature-ului. schema proprie (doar
    "protocol", nu protocol_type/service/flag ca la modelul vechi) -
    functie separata, NU reutilizeaza pe cea din nids.ml.expert.model, ca
    sa nu lege cele doua sisteme intre ele"""
    for category in CATEGORICAL_COLUMNS:
        if column.startswith(category + "_"):
            return category
    return column


def build_metrics(y_test, y_pred) -> dict[str, float]:
    """calculeaza performanta pe test set intr-un singur loc, reutilizat
    atat de scripts/train_modern_expert_model.py (antrenare initiala) cat
    si de nids/ml/modern/retrain.py (reantrenare din honeypot) - ca cele
    doua cai sa nu poata ajunge sa calculeze metricile diferit intre ele"""
    report = classification_report(
        y_test, y_pred, target_names=["normal", "atac"], output_dict=True
    )
    return {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "normal_precision": float(report["normal"]["precision"]),
        "normal_recall": float(report["normal"]["recall"]),
        "attack_precision": float(report["atac"]["precision"]),
        "attack_recall": float(report["atac"]["recall"]),
    }


class ModernExpertModel:
    """model pre-antrenat pe CSE-CIC-IDS2018 (schema CICFlowMeter, vezi
    nids.ml.modern.dataset) - complet separat de ExpertModel (NSL-KDD).
    ruleaza ALATURI de modelul vechi, ca "a doua opinie", nu il inlocuieste
    si nu e integrat in logica de combinare (Agreement) existenta - vezi
    DATASET-COMPARISON.md"""

    def __init__(
        self,
        model: RandomForestClassifier,
        feature_columns: list[str],
        metrics: dict[str, float] | None = None,
    ) -> None:
        self._model = model
        self._feature_columns = feature_columns
        # performanta pe propriul test set, calculata la (re)antrenare -
        # salvata ALATURI de model (nu hardcodata in UI) ca sa ramana
        # mereu adevarata dupa o reantrenare din honeypot, care schimba
        # efectiv acuratetea - vezi scripts/train_modern_expert_model.py
        # si nids/ml/modern/retrain.py. None pentru modele salvate inainte
        # de acest camp (backward compatibil)
        self._metrics = metrics

    @property
    def metrics(self) -> dict[str, float] | None:
        return self._metrics

    @classmethod
    def load(cls, path: Path = DEFAULT_MODEL_PATH) -> ModernExpertModel:
        payload = joblib.load(path)
        return cls(payload["model"], payload["feature_columns"], payload.get("metrics"))

    def save(self, path: Path = DEFAULT_MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self._model,
                "feature_columns": self._feature_columns,
                "metrics": self._metrics,
            },
            path,
        )

    def predict(self, features: pd.DataFrame) -> list[int]:
        aligned = features.reindex(columns=self._feature_columns, fill_value=0)
        return list(self._model.predict(aligned))

    def explain(
        self, encoded: pd.DataFrame, raw_values: dict, top_n: int = 8
    ) -> list[FeatureContribution]:
        """vezi ExpertModel.explain() - acelasi principiu (importanta
        GLOBALA a modelului, nu specifica conexiunii), doar independenta
        ca implementare"""
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
