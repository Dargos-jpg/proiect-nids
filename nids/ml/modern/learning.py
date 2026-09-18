from __future__ import annotations

import statistics
from dataclasses import dataclass
from pathlib import Path

import joblib

from nids.ml.features.cicflow_style import CicFlowFeatures
from nids.ml.modern.local import ModernLocalModel

MIN_TRAINING_SAMPLES = 50
RETRAIN_EVERY_N_SAMPLES = 25
MAX_BUFFER_SIZE = 10000  # vezi NOTES.md - aceeasi valoare/motivatie ca la modelul local vechi
DEFAULT_N_ESTIMATORS = 100

# subset de features numerice reprezentative din schema CICFlowMeter (72
# features) - evita campurile aproape mereu 0/redundante (ex. cele de
# "transfer in bloc", deja excluse din schema, sau Fwd/Bwd Header Len,
# aproximate constant per pachet - vezi cicflow_style.py)
EXPLAIN_FEATURES = [
    "flow_duration",
    "totlen_fwd_pkts",
    "totlen_bwd_pkts",
    "flow_byts_per_s",
    "flow_pkts_per_s",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "pkt_len_mean",
    "down_up_ratio",
]

# o singura coloana categorica in schema noua (vezi nids.ml.modern.dataset.CATEGORICAL_COLUMNS)
CATEGORICAL_EXPLAIN_FEATURES = ["protocol"]


@dataclass
class FeatureDeviation:
    feature: str
    value: float
    baseline_mean: float
    baseline_std: float
    z_score: float


@dataclass
class CategoricalRarity:
    feature: str
    value: str
    frequency: float


DEFAULT_STATE_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "data"
    / "models"
    / "modern_local_model_state.joblib"
)


class ModernLocalModelManager:
    """echivalentul lui nids.ml.local.learning.LocalModelManager, dar pe
    schema CicFlowFeatures (CSE-CIC-IDS2018) - acelasi ciclu de viata
    (cold start -> activ, fereastra glisanta, reantrenare periodica,
    persistenta pe disc intre sesiuni), complet separat de modelul local
    vechi (NSL-KDD). vezi DATASET-COMPARISON.md pentru motivatia
    arhitecturii duale (vechi + modern, fara sa se amestece)"""

    def __init__(
        self,
        min_training_samples: int = MIN_TRAINING_SAMPLES,
        retrain_every: int = RETRAIN_EVERY_N_SAMPLES,
        max_buffer_size: int = MAX_BUFFER_SIZE,
        contamination: float | None = None,
        n_estimators: int = DEFAULT_N_ESTIMATORS,
    ) -> None:
        self._min_training_samples = min_training_samples
        self._retrain_every = retrain_every
        self._max_buffer_size = max_buffer_size
        self._contamination = contamination
        self._n_estimators = n_estimators
        self._buffer: list[CicFlowFeatures] = []
        self._model: ModernLocalModel | None = None
        self._new_since_retrain = 0

    @property
    def is_learning(self) -> bool:
        return self._model is None

    @property
    def samples_collected(self) -> int:
        return len(self._buffer)

    @property
    def min_training_samples(self) -> int:
        return self._min_training_samples

    def process(self, record: CicFlowFeatures) -> int | None:
        self._buffer.append(record)
        if len(self._buffer) > self._max_buffer_size:
            self._buffer.pop(0)

        if self._model is None:
            if len(self._buffer) < self._min_training_samples:
                return None
            self._retrain()
        else:
            self._new_since_retrain += 1
            if self._new_since_retrain >= self._retrain_every:
                self._retrain()

        return self._model.predict([record])[0]

    def predict_only(self, record: CicFlowFeatures) -> int | None:
        if self._model is None:
            return None
        return self._model.predict([record])[0]

    def anomaly_score(self, record: CicFlowFeatures) -> float | None:
        if self._model is None:
            return None
        return self._model.anomaly_score([record])[0]

    def explain(self, record: CicFlowFeatures) -> list[FeatureDeviation]:
        if not self._buffer:
            return []

        deviations = []
        for name in EXPLAIN_FEATURES:
            values = [getattr(r, name) for r in self._buffer]
            mean = statistics.fmean(values)
            std = statistics.pstdev(values) if len(values) > 1 else 0.0
            value = getattr(record, name)
            z_score = (value - mean) / std if std > 0 else 0.0
            deviations.append(
                FeatureDeviation(
                    feature=name,
                    value=value,
                    baseline_mean=mean,
                    baseline_std=std,
                    z_score=z_score,
                )
            )

        deviations.sort(key=lambda d: abs(d.z_score), reverse=True)
        return deviations

    def explain_categorical(self, record: CicFlowFeatures) -> list[CategoricalRarity]:
        if not self._buffer:
            return []

        rarities = []
        for name in CATEGORICAL_EXPLAIN_FEATURES:
            value = getattr(record, name)
            matching = sum(1 for r in self._buffer if getattr(r, name) == value)
            frequency = matching / len(self._buffer)
            rarities.append(CategoricalRarity(feature=name, value=value, frequency=frequency))

        rarities.sort(key=lambda r: r.frequency)
        return rarities

    def _retrain(self) -> None:
        contamination = self._contamination if self._contamination is not None else "auto"
        self._model = ModernLocalModel.train(
            self._buffer, contamination=contamination, n_estimators=self._n_estimators
        )
        self._new_since_retrain = 0

    def save(self, path: Path | None = None) -> None:
        if self._model is None:
            raise RuntimeError("modelul local modern nu e inca antrenat - inca in modul invatare")
        target = path if path is not None else DEFAULT_STATE_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "buffer": self._buffer}, target)

    @classmethod
    def load(cls, path: Path | None = None, **kwargs) -> ModernLocalModelManager:
        target = path if path is not None else DEFAULT_STATE_PATH
        payload = joblib.load(target)
        manager = cls(**kwargs)
        manager._model = payload["model"]
        manager._buffer = payload["buffer"]
        return manager

    @classmethod
    def load_or_new(cls, path: Path | None = None, **kwargs) -> ModernLocalModelManager:
        try:
            return cls.load(path, **kwargs)
        except FileNotFoundError:
            return cls(**kwargs)
