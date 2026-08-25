from __future__ import annotations

from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest

from nids.ml.expert.nsl_kdd import encode_features
from nids.ml.features.nsl_kdd_style import NslKddStyleFeatures, to_feature_frame

DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "data"
    / "models"
    / "local_isolation_forest.joblib"
)


class LocalModel:
    """model de anomalii antrenat DOAR pe traficul capturat de
    utilizator - nu stie nimic despre atacuri "din carte", invata doar
    ce e normal pentru reteaua asta. foloseste acelasi set de 28
    features ca modelul expert (nids.ml.features.nsl_kdd_style), ca sa
    poata fi comparate direct la pasul urmator (dezacord intre modele)"""

    def __init__(self, model: IsolationForest, feature_columns: list[str]) -> None:
        self._model = model
        self._feature_columns = feature_columns

    @classmethod
    def train(
        cls,
        records: list[NslKddStyleFeatures],
        contamination: float | str = "auto",
        n_estimators: int = 100,
    ) -> LocalModel:
        """contamination = rata asteptata de anomalii in date - controleaza
        direct cat de usor Isolation Forest marcheaza ceva drept anomalie
        (mai mare = mai sensibil). 'auto' e euristica default din sklearn.

        n_estimators = numarul de arbori (izolatori aleatori) din padure -
        100 e implicitul sklearn. mai multi arbori inseamna scoruri de
        anomalie mai stabile (medie peste mai multe partitionari aleatoare,
        mai putina varianta intre reantrenari succesive), cu cost liniar in
        timp de antrenare - nu are un "corect" universal, depinde de
        volumul si eterogenitatea traficului, de-asta e configurabil"""
        raw = to_feature_frame(records)
        encoded = encode_features(raw)
        model = IsolationForest(
            random_state=42, contamination=contamination, n_estimators=n_estimators
        )
        model.fit(encoded)
        return cls(model, list(encoded.columns))

    @classmethod
    def load(cls, path: Path = DEFAULT_MODEL_PATH) -> LocalModel:
        payload = joblib.load(path)
        return cls(payload["model"], payload["feature_columns"])

    def save(self, path: Path = DEFAULT_MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "feature_columns": self._feature_columns}, path)

    def predict(self, records: list[NslKddStyleFeatures]) -> list[int]:
        """1 = anomalie, 0 = normal - acelasi sens ca ExpertModel.predict,
        desi scikit-learn foloseste intern -1/1 pentru Isolation Forest"""
        if not records:
            return []
        raw = to_feature_frame(records)
        encoded = encode_features(raw, encoded_columns=self._feature_columns)
        raw_predictions = self._model.predict(encoded)
        return [1 if p == -1 else 0 for p in raw_predictions]

    def anomaly_score(self, records: list[NslKddStyleFeatures]) -> list[float]:
        """scor CONTINUU de anomalie, nu doar binarul din predict() - mai
        mare = mai anormal (conventie proprie: inversul lui
        decision_function() din sklearn, unde NEGATIV inseamna anomalie).
        util pentru severitate graduala (usor/moderat/sever), nu doar
        "e sau nu e anomalie peste pragul de contamination" """
        if not records:
            return []
        raw = to_feature_frame(records)
        encoded = encode_features(raw, encoded_columns=self._feature_columns)
        return [-score for score in self._model.decision_function(encoded)]
