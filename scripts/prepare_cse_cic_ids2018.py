from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

# scripturile ruleaza direct (nu ca modul python -m), asa ca radacina
# proiectului trebuie adaugata manual pe sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw" / "cse-cic-ids2018"
OUT_DIR = RAW_DIR / "processed"

# marti 20-02-2018 (ziua de DDoS masiv) are un antet cu 4 coloane in plus
# fata de restul fisierelor (Flow ID, Src IP, Src Port, Dst IP) - descoperit
# prin verificare directa, nu presupus (vezi DATASET-COMPARISON.md).
# aliniem la schema standard de 80 coloane, eliminandu-le
_EXTRA_IDENTIFICATION_COLUMNS = ["Flow ID", "Src IP", "Src Port", "Dst IP"]

# esantionare stratificata: fiecare CLASA (Benign + fiecare tip de atac) e
# plafonata la acest numar de randuri - claselor cu mai putine randuri
# decat plafonul li se pastreaza TOATE (ex: SQL Injection, doar 87 randuri
# in tot setul). implementare: "pool" per clasa care creste pe masura ce
# citim fisierele in bucati (chunk-uri) si se reduce periodic (esantionare
# aleatoare vectorizata pandas) cand depaseste un multiplu al plafonului -
# NU reservoir sampling clasic (Algorithm R) rand-cu-rand, care ar fi mult
# prea lent (peste 16 milioane de randuri in total, iterrows() ar dura
# ordine de marime mai mult decat operatiile vectorizate pandas.sample())
SAMPLES_PER_CLASS = 50_000
# BUG real gasit dupa prima antrenare (vezi BUGS.md): plafonand "Benign" la
# ACELASI numar ca fiecare clasa de atac, setul de antrenare a iesit cu
# ~40k normal vs ~364k atac (raport 9:1) - INVERSUL realitatii (83% din
# trafic e normal). rezultat masurat: model cu 96% precizie/recall pe
# "atac" dar doar 62%/65% pe "normal" - exact tiparul de model antrenat
# sa "vada" prea putin trafic normal ca sa-l recunoasca bine. fix: Benign
# primeste un plafon mult mai mare, apropiat de TOTALUL claselor de atac
# (~450k), ca raportul normal/atac din antrenare sa nu fie complet opus
# realitatii - nu perfect 83/17 ca in setul original (ar cere sute de mii
# de randuri suplimentare doar pentru normal, fara beneficiu clar pentru
# un RandomForest), dar nici extrem invers
_PER_CLASS_CAPACITY_OVERRIDES = {"Benign": 450_000}
_POOL_TRIGGER_MULTIPLIER = 3  # reducem pool-ul cand trece de 3x plafonul
TRAIN_FRACTION = 0.8
RANDOM_SEED = 42
CHUNK_SIZE = 200_000


class _ClassPool:
    """acumuleaza randuri pentru O SINGURA eticheta, reducandu-se periodic
    printr-o esantionare aleatoare (vectorizata) cand creste prea mult -
    tine memoria marginita indiferent cat de mare e clasa in fisierul
    original (ex: Benign, 13.48 milioane de randuri in tot setul)"""

    def __init__(self, capacity: int, seed: int) -> None:
        self.capacity = capacity
        self._seed = seed
        self.seen = 0
        self._pool: pd.DataFrame | None = None

    def add(self, rows: pd.DataFrame) -> None:
        self.seen += len(rows)
        self._pool = rows if self._pool is None else pd.concat([self._pool, rows], ignore_index=True)
        if len(self._pool) > self.capacity * _POOL_TRIGGER_MULTIPLIER:
            self._pool = self._pool.sample(n=self.capacity, random_state=self._seed).reset_index(
                drop=True
            )

    def finalize(self) -> pd.DataFrame:
        if self._pool is None:
            return pd.DataFrame()
        if len(self._pool) > self.capacity:
            return self._pool.sample(n=self.capacity, random_state=self._seed).reset_index(drop=True)
        return self._pool


def _clean_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    """elimina randurile-gunoi (antet duplicat inline in date - "Label" ca
    valoare de eticheta, gasit empiric, cunoscut in literatura despre acest
    dataset) si randurile cu valori Infinity/NaN pe coloanele numerice
    (gasite empiric pe coloanele de rata Flow Byts/s si Flow Pkts/s -
    impartiri la zero din CICFlowMeter original).

    BUG gasit la prima rulare: "Timestamp" (string de tip data, ex.
    "01/03/2018 08:17:11") NU e numeric - inclus gresit in verificarea de
    finitudine, `pd.to_numeric` il transforma in NaN pentru ORICE rand,
    respingand 100% din date. "Timestamp" e identificare, nu feature (nici
    nu ajunge in COLUMN_RENAME_MAP din dataset.py) - eliminat explicit
    aici, inainte de verificarea de finitudine, nu doar mai tarziu"""
    chunk = chunk[chunk["Label"] != "Label"].copy()
    if chunk.empty:
        return chunk
    chunk = chunk.drop(columns=["Timestamp"], errors="ignore")

    feature_columns = [c for c in chunk.columns if c != "Label"]
    numeric = chunk[feature_columns].apply(pd.to_numeric, errors="coerce")
    finite_mask = numeric.apply(np.isfinite).all(axis=1)
    chunk = chunk[finite_mask].copy()
    chunk[feature_columns] = numeric[finite_mask]
    return chunk


def _sample_file(path: Path, pools: dict[str, _ClassPool]) -> None:
    print(f"procesez {path.name}...")
    is_misaligned = path.name.startswith("Thuesday")
    for chunk in pd.read_csv(path, chunksize=CHUNK_SIZE, low_memory=False):
        if is_misaligned:
            chunk = chunk.drop(columns=_EXTRA_IDENTIFICATION_COLUMNS, errors="ignore")

        chunk = _clean_chunk(chunk)
        if chunk.empty:
            continue

        for label, group in chunk.groupby("Label"):
            capacity = _PER_CLASS_CAPACITY_OVERRIDES.get(label, SAMPLES_PER_CLASS)
            pool = pools.setdefault(label, _ClassPool(capacity, RANDOM_SEED))
            pool.add(group)


def main() -> None:
    files = sorted(RAW_DIR.glob("*.csv"))
    if not files:
        raise SystemExit(f"niciun CSV gasit in {RAW_DIR} - descarca intai setul de date")

    pools: dict[str, _ClassPool] = {}
    for f in files:
        _sample_file(f, pools)

    print("\nesantioane per clasa (dupa reducere):")
    train_frames = []
    test_frames = []
    for label, pool in sorted(pools.items(), key=lambda kv: -kv[1].seen):
        df = pool.finalize().sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
        split_at = int(len(df) * TRAIN_FRACTION)
        train_frames.append(df.iloc[:split_at])
        test_frames.append(df.iloc[split_at:])
        print(f"  {label}: {pool.seen} randuri valide vazute -> {len(df)} esantionate")

    train_df = (
        pd.concat(train_frames, ignore_index=True)
        .sample(frac=1.0, random_state=RANDOM_SEED)
        .reset_index(drop=True)
    )
    test_df = (
        pd.concat(test_frames, ignore_index=True)
        .sample(frac=1.0, random_state=RANDOM_SEED)
        .reset_index(drop=True)
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    train_path = OUT_DIR / "train.csv"
    test_path = OUT_DIR / "test.csv"
    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)

    print(f"\nscris {len(train_df)} randuri in {train_path}")
    print(f"scris {len(test_df)} randuri in {test_path}")


if __name__ == "__main__":
    main()
