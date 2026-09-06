from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

from nids.capture.packet_meta import PacketMeta
from nids.ml.expert.model import DEFAULT_MODEL_PATH, ExpertModel
from nids.ml.expert.nsl_kdd import encode_features, load_dataset, prepare_features
from nids.ml.features.nsl_kdd_style import extract_nsl_kdd_style_features, to_feature_frame

_DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data" / "raw" / "nsl-kdd"
DEFAULT_TRAIN_PATH = _DATA_DIR / "KDDTrain+.txt"
DEFAULT_TEST_PATH = _DATA_DIR / "KDDTest+.txt"

# prag arbitrar, nu calibrat statistic (la fel ca MIN_TRAINING_SAMPLES la
# modelul local) - doar suficient sa existe un minim de semnal inainte sa
# merite sa reantrenam un RandomForest intreg pentru cateva conexiuni
MIN_HONEYPOT_SAMPLES = 10


@dataclass
class RetrainResult:
    honeypot_connections_used: int
    accuracy_before: float
    accuracy_after: float
    model_saved: bool


def _is_at_least_as_good(accuracy_before: float, accuracy_after: float) -> bool:
    """decizia de a suprascrie modelul activ - separata intr-o functie
    pura, usor de testat fara sa antrenam vreun RandomForest real. se
    apeleaza DOAR cand exista deja un model activ de protejat - cazul
    "niciun model inca" (prima reantrenare) se trateaza separat, in
    retrain_with_honeypot_data(), pentru ca acolo nu exista nimic de
    "stricat" si se salveaza neconditionat"""
    return accuracy_after >= accuracy_before


def retrain_with_honeypot_data(
    honeypot_packets: list[PacketMeta],
    train_path: Path = DEFAULT_TRAIN_PATH,
    test_path: Path = DEFAULT_TEST_PATH,
    model_out_path: Path = DEFAULT_MODEL_PATH,
    n_estimators: int = 200,
) -> RetrainResult:
    """reantreneaza modelul expert adaugand conexiunile honeypot peste
    setul static NSL-KDD - etichetate INTOTDEAUNA "atac", fara exceptie
    (niciun serviciu legitim nu asculta pe porturile honeypot, spre
    deosebire de restul aplicatiei unde exista mereu risc de fals-pozitiv).

    compara acuratetea NOULUI model, pe ACELASI KDDTest+, cu a modelului
    ACTIV curent (cel deja salvat pe disc, nu un baseline antrenat din nou
    doar pentru comparatie) - daca noul model iese mai slab, NU suprascrie
    modelul activ. userul a semnalat corect ca datele honeypot (putine,
    structural asemanatoare intre ele - vezi hit_to_packets) ar putea sa
    "inguste" ce a invatat modelul in loc sa il imbunatateasca; fara aceasta
    garda, userul ar fi trebuit sa observe singur o scadere de acuratete si
    sa restaureze manual din backup-ul .bak - acum aplicatia decide singura
    sa NU faca o schimbare care s-ar dovedi o regresie masurabila.

    face backup (.bak) al modelului anterior INAINTE sa suprascrie, DOAR
    cand chiar suprascrie - reantrenarea trebuie sa fie la fel de
    reversibila ca o blocare de IP, nu o operatie definitiva"""
    train_df = load_dataset(train_path)
    test_df = load_dataset(test_path)

    x_train, y_train = prepare_features(train_df)
    x_test, y_test = prepare_features(test_df, encoded_columns=list(x_train.columns))

    honeypot_records = extract_nsl_kdd_style_features(honeypot_packets)
    honeypot_raw = to_feature_frame(honeypot_records)
    honeypot_encoded = encode_features(honeypot_raw, encoded_columns=list(x_train.columns))
    honeypot_labels = pd.Series([1] * len(honeypot_encoded))

    x_combined = pd.concat([x_train, honeypot_encoded], ignore_index=True)
    y_combined = pd.concat([y_train.reset_index(drop=True), honeypot_labels], ignore_index=True)

    new_model = RandomForestClassifier(n_estimators=n_estimators, random_state=42, n_jobs=-1)
    new_model.fit(x_combined, y_combined)
    accuracy_after = float(accuracy_score(y_test, new_model.predict(x_test)))

    model_exists = model_out_path.exists()
    if model_exists:
        # comparam cu modelul CHIAR ACTIV (poate contine deja date honeypot
        # dintr-o reantrenare anterioara) - nu cu un baseline nou-antrenat
        # doar din NSL-KDD, care ar ignora orice imbunatatire anterioara
        current_model = ExpertModel.load(model_out_path)
        accuracy_before = float(accuracy_score(y_test, current_model.predict(x_test)))
        model_saved = _is_at_least_as_good(accuracy_before, accuracy_after)
    else:
        # niciun model activ inca - nimic de protejat, prima reantrenare se
        # salveaza necondiționat. antrenam totusi un baseline doar din
        # NSL-KDD ca sa avem o cifra reala de comparatie in mesajul din UI
        baseline_model = RandomForestClassifier(n_estimators=n_estimators, random_state=42, n_jobs=-1)
        baseline_model.fit(x_train, y_train)
        accuracy_before = float(accuracy_score(y_test, baseline_model.predict(x_test)))
        model_saved = True

    if model_saved:
        if model_exists:
            backup_path = model_out_path.with_suffix(model_out_path.suffix + ".bak")
            backup_path.write_bytes(model_out_path.read_bytes())
        ExpertModel(new_model, list(x_train.columns)).save(model_out_path)

    return RetrainResult(
        honeypot_connections_used=len(honeypot_records),
        accuracy_before=accuracy_before,
        accuracy_after=accuracy_after,
        model_saved=model_saved,
    )
