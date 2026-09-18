from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

from nids.capture.packet_meta import PacketMeta
from nids.ml.features.cicflow_style import extract_cicflow_features, to_feature_frame
from nids.ml.modern.dataset import encode_features, load_dataset, prepare_features
from nids.ml.modern.model import DEFAULT_MODEL_PATH, ModernExpertModel, build_metrics

_DATA_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "data"
    / "raw"
    / "cse-cic-ids2018"
    / "processed"
)
DEFAULT_TRAIN_PATH = _DATA_DIR / "train.csv"
DEFAULT_TEST_PATH = _DATA_DIR / "test.csv"

# acelasi prag ca la sistemul vechi (nids.ml.expert.retrain) - arbitrar,
# doar suficient sa existe un minim de semnal
MIN_HONEYPOT_SAMPLES = 10

# fara el, un RandomForest antrenat pe 724k+ randuri (CSE-CIC-IDS2018) creste
# nelimitat - lectie directa din BUGS.md (modelul initial a ajuns la 1.18 GB,
# a incetinit toata suita de teste la peste 5 minute). 50 a fost dovedit
# empiric ca nu pierde acuratete reala (vezi scripts/train_modern_expert_model.py)
DEFAULT_MIN_SAMPLES_LEAF = 50


@dataclass
class RetrainResult:
    honeypot_connections_used: int
    accuracy_before: float
    accuracy_after: float
    model_saved: bool


def _is_at_least_as_good(accuracy_before: float, accuracy_after: float) -> bool:
    """vezi nids.ml.expert.retrain._is_at_least_as_good() - acelasi
    principiu, implementare separata (nu leaga cele doua sisteme)"""
    return accuracy_after >= accuracy_before


def retrain_with_honeypot_data(
    honeypot_packets: list[PacketMeta],
    train_path: Path = DEFAULT_TRAIN_PATH,
    test_path: Path = DEFAULT_TEST_PATH,
    model_out_path: Path = DEFAULT_MODEL_PATH,
    n_estimators: int = 200,
    min_samples_leaf: int = DEFAULT_MIN_SAMPLES_LEAF,
) -> RetrainResult:
    """echivalentul nids.ml.expert.retrain.retrain_with_honeypot_data(),
    dar reantreneaza modelul MODERN (CSE-CIC-IDS2018) - devenit principal
    in Faza 6 (DATASET-COMPARISON.md). honeypot-ul e etichetat la fel,
    intotdeauna "atac" (niciun serviciu legitim nu asculta pe porturile
    honeypot). aceleasi pachete sintetice (nids.honeypot.training_data.hit_to_packets,
    generice - PacketMeta simplu) merg si aici, si la sistemul vechi - doar
    extractorul de features difera (cicflow_style, nu nsl_kdd_style)

    aceeasi poarta de siguranta ca la sistemul vechi: NU suprascrie modelul
    activ daca acuratetea pe testul propriu scade fata de modelul CHIAR
    activ (nu un baseline nou-antrenat doar pentru comparatie)"""
    train_df = load_dataset(train_path)
    test_df = load_dataset(test_path)

    x_train, y_train = prepare_features(train_df)
    x_test, y_test = prepare_features(test_df, encoded_columns=list(x_train.columns))

    honeypot_records = extract_cicflow_features(honeypot_packets)
    honeypot_raw = to_feature_frame(honeypot_records)
    honeypot_encoded = encode_features(honeypot_raw, encoded_columns=list(x_train.columns))
    honeypot_labels = pd.Series([1] * len(honeypot_encoded))

    x_combined = pd.concat([x_train, honeypot_encoded], ignore_index=True)
    y_combined = pd.concat([y_train.reset_index(drop=True), honeypot_labels], ignore_index=True)

    new_model = RandomForestClassifier(
        n_estimators=n_estimators,
        min_samples_leaf=min_samples_leaf,
        random_state=42,
        n_jobs=-1,
    )
    new_model.fit(x_combined, y_combined)
    new_predictions = new_model.predict(x_test)
    accuracy_after = float(accuracy_score(y_test, new_predictions))

    model_exists = model_out_path.exists()
    if model_exists:
        current_model = ModernExpertModel.load(model_out_path)
        accuracy_before = float(accuracy_score(y_test, current_model.predict(x_test)))
        model_saved = _is_at_least_as_good(accuracy_before, accuracy_after)
    else:
        baseline_model = RandomForestClassifier(
            n_estimators=n_estimators,
            min_samples_leaf=min_samples_leaf,
            random_state=42,
            n_jobs=-1,
        )
        baseline_model.fit(x_train, y_train)
        accuracy_before = float(accuracy_score(y_test, baseline_model.predict(x_test)))
        model_saved = True

    if model_saved:
        if model_exists:
            backup_path = model_out_path.with_suffix(model_out_path.suffix + ".bak")
            backup_path.write_bytes(model_out_path.read_bytes())
        metrics = build_metrics(y_test, new_predictions)
        ModernExpertModel(new_model, list(x_train.columns), metrics=metrics).save(model_out_path)

    return RetrainResult(
        honeypot_connections_used=len(honeypot_records),
        accuracy_before=accuracy_before,
        accuracy_after=accuracy_after,
        model_saved=model_saved,
    )
