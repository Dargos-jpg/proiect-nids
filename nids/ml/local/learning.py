from __future__ import annotations

from pathlib import Path

from nids.ml.features.nsl_kdd_style import NslKddStyleFeatures
from nids.ml.local.model import LocalModel

MIN_TRAINING_SAMPLES = 500


class LocalModelManager:
    """gestioneaza ciclul de viata al modelului local: cold start - la
    inceput nu are date, doar colecteaza traficul (modul "invatare", nu
    marcheaza nimic ca anomalie) pana aduna suficiente exemple, apoi
    antreneaza modelul si trece in modul activ. vezi CONTEXT-nids.md,
    sectiunea "cold start pe modelul local".

    nu retraneaza periodic (concept drift, mentionat tot in context, ca
    problema cunoscuta) - antrenarea se intampla o singura data, cand se
    atinge pragul; reantrenare periodica ramane pentru mai tarziu"""

    def __init__(self, min_training_samples: int = MIN_TRAINING_SAMPLES) -> None:
        self._min_training_samples = min_training_samples
        self._buffer: list[NslKddStyleFeatures] = []
        self._model: LocalModel | None = None

    @property
    def is_learning(self) -> bool:
        return self._model is None

    @property
    def samples_collected(self) -> int:
        return len(self._buffer)

    def process(self, record: NslKddStyleFeatures) -> int | None:
        """intoarce None cat timp e in modul invatare (nu evalueaza
        inca), altfel 1 (anomalie) sau 0 (normal)"""
        if self._model is not None:
            return self._model.predict([record])[0]

        self._buffer.append(record)
        if len(self._buffer) >= self._min_training_samples:
            self._model = LocalModel.train(self._buffer)
            self._buffer = []
            return self._model.predict([record])[0]

        return None

    def save(self, path: Path | None = None) -> None:
        if self._model is None:
            raise RuntimeError("modelul local nu e inca antrenat - inca in modul invatare")
        if path is not None:
            self._model.save(path)
        else:
            self._model.save()
