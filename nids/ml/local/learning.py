from __future__ import annotations

import statistics
from dataclasses import dataclass
from pathlib import Path

import joblib

from nids.ml.features.nsl_kdd_style import NslKddStyleFeatures
from nids.ml.local.model import LocalModel

MIN_TRAINING_SAMPLES = 50
RETRAIN_EVERY_N_SAMPLES = 25
MAX_BUFFER_SIZE = 2000
DEFAULT_N_ESTIMATORS = 100  # implicitul sklearn - vezi LocalModel.train()

# subset de features numerice folosite pentru explicatia "cat de departe
# de normal" - reprezentative din ambele categorii (basic + traffic),
# evita campurile aproape mereu 0 (land, wrong_fragment, urgent)
EXPLAIN_FEATURES = [
    "src_bytes",
    "dst_bytes",
    "duration",
    "count",
    "srv_count",
    "serror_rate",
    "rerror_rate",
    "dst_host_count",
    "dst_host_serror_rate",
]

# Isolation Forest vede si coloanele categorice (encodate one-hot), nu
# doar cele numerice de mai sus - o combinatie categorica rara poate fi
# motivul real al unei anomalii chiar daca niciun numar individual nu
# pare extrem (ex: trafic UDP catre o adresa multicast, quasi-inexistent
# in bufferul de HTTP/HTTPS obisnuit - vezi discutia cu userul)
CATEGORICAL_EXPLAIN_FEATURES = ["protocol_type", "service", "flag"]


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
    frequency: float  # fractia din buffer cu aceeasi valoare, 0.0-1.0


DEFAULT_STATE_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "data"
    / "models"
    / "local_model_state.joblib"
)


class LocalModelManager:
    """gestioneaza ciclul de viata al modelului local: cold start - la
    inceput nu are date, doar colecteaza traficul (modul "invatare", nu
    marcheaza nimic ca anomalie) pana aduna suficiente exemple, apoi
    antreneaza modelul si trece in modul activ. vezi CONTEXT-nids.md,
    sectiunea "cold start pe modelul local".

    dupa ce devine activ, NU ramane inghetat - retraneaza periodic (la
    fiecare RETRAIN_EVERY_N_SAMPLES conexiuni noi) pe o fereastra
    glisanta de pana la MAX_BUFFER_SIZE conexiuni recente. fereastra
    glisanta (nu tot istoricul) e si raspunsul la concept drift -
    comportamentul "normal" al retelei se schimba in timp, traficul
    foarte vechi iese din fereastra si nu mai influenteaza modelul.

    starea (model + buffer) se salveaza/incarca de pe disc, ca invatarea
    sa NU se piarda la fiecare repornire a monitorizarii - altfel fiecare
    sesiune ar reincepe de la zero, ineficient (userul a semnalat asta
    explicit)"""

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
        self._buffer: list[NslKddStyleFeatures] = []
        self._model: LocalModel | None = None
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

    def process(self, record: NslKddStyleFeatures) -> int | None:
        """intoarce None cat timp e in modul invatare (nu evalueaza
        inca), altfel 1 (anomalie) sau 0 (normal)"""
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

    def predict_only(self, record: NslKddStyleFeatures) -> int | None:
        """prezice fara sa modifice bufferul sau sa declanseze
        reantrenare - pentru inspectie manuala la cerere. process() e
        pentru fluxul normal, ACTUALIZEAZA starea; asta nu"""
        if self._model is None:
            return None
        return self._model.predict([record])[0]

    def anomaly_score(self, record: NslKddStyleFeatures) -> float | None:
        """scor continuu de anomalie (vezi LocalModel.anomaly_score) -
        None cat timp modelul e inca in modul invatare, la fel ca
        predict_only(). NU modifica bufferul - safe de apelat oricand,
        atat din fluxul live (dupa process()) cat si din inspectia la
        cerere"""
        if self._model is None:
            return None
        return self._model.anomaly_score([record])[0]

    def explain(self, record: NslKddStyleFeatures) -> list[FeatureDeviation]:
        """compara valorile conexiunii cu media/deviatia standard din
        fereastra curenta de trafic "normal". Isolation Forest n-are o
        explicatie nativa per-feature (spre deosebire de Random Forest) -
        asta e o aproximare simpla, fara nicio dependinta noua: cat de
        departe e fiecare valoare fata de ce e tipic pentru reteaua asta"""
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

    def explain_categorical(self, record: NslKddStyleFeatures) -> list[CategoricalRarity]:
        """cat de RARA e combinatia categorica a acestei conexiuni
        (protocol, serviciu, stare/flag) fata de fereastra curenta -
        vezi CATEGORICAL_EXPLAIN_FEATURES. frecventa mica = valoare
        neobisnuita in bufferul actual, posibil motivul real al unei
        anomalii pe care explain() (doar numeric) n-o poate arata"""
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
        self._model = LocalModel.train(
            self._buffer, contamination=contamination, n_estimators=self._n_estimators
        )
        self._new_since_retrain = 0

    def save(self, path: Path | None = None) -> None:
        if self._model is None:
            raise RuntimeError("modelul local nu e inca antrenat - inca in modul invatare")
        # rezolvat aici, nu ca valoare implicita de parametru - altfel
        # monkeypatch pe DEFAULT_STATE_PATH in teste n-ar avea efect
        # (valoarea implicita s-ar "inghetat" la momentul definirii)
        target = path if path is not None else DEFAULT_STATE_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "buffer": self._buffer}, target)

    @classmethod
    def load(cls, path: Path | None = None, **kwargs) -> LocalModelManager:
        target = path if path is not None else DEFAULT_STATE_PATH
        payload = joblib.load(target)
        manager = cls(**kwargs)
        manager._model = payload["model"]
        manager._buffer = payload["buffer"]
        return manager

    @classmethod
    def load_or_new(cls, path: Path | None = None, **kwargs) -> LocalModelManager:
        """incearca sa continue de unde a ramas o sesiune anterioara -
        daca nu exista nimic salvat, porneste de la zero (cold start)"""
        try:
            return cls.load(path, **kwargs)
        except FileNotFoundError:
            return cls(**kwargs)
