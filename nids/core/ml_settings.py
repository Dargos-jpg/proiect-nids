from __future__ import annotations

from dataclasses import dataclass

from nids.ml.local.learning import (
    DEFAULT_N_ESTIMATORS,
    MAX_BUFFER_SIZE,
    MIN_TRAINING_SAMPLES,
    RETRAIN_EVERY_N_SAMPLES,
)

DEFAULT_EVALUATION_INTERVAL_MS = 5000


@dataclass
class MlSettings:
    """setari ajustabile din panoul ML, impartite intre MlPanel (le
    modifica) si DashboardPanel (le citeste) - un obiect simplu de date,
    nu un widget, tocmai ca sa evite o dependinta circulara intre cele
    doua (MlPanel are nevoie de DashboardPanel pentru starea live a
    modelelor, DashboardPanel are nevoie de setarile din MlPanel la
    pornirea monitorizarii - vezi MainWindow pentru firul de asamblare).

    la fel ca pragul de port scan din SignaturesPanel, se citesc din nou
    doar la inceputul unei sesiuni noi de monitorizare - o schimbare nu
    se aplica live, in mijlocul unei sesiuni deja pornite"""

    min_training_samples: int = MIN_TRAINING_SAMPLES
    retrain_every: int = RETRAIN_EVERY_N_SAMPLES
    max_buffer_size: int = MAX_BUFFER_SIZE
    contamination: float | None = None  # None = 'auto' (implicit sklearn)
    n_estimators: int = DEFAULT_N_ESTIMATORS  # numar de arbori Isolation Forest
    strict_reporting: bool = False  # True = raporteaza doar cand ambele modele sunt de acord
    evaluation_interval_ms: int = DEFAULT_EVALUATION_INTERVAL_MS
