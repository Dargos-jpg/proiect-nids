from __future__ import annotations

import sys
from pathlib import Path

# scripturile ruleaza direct (nu ca modul python -m), asa ca radacina
# proiectului trebuie adaugata manual pe sys.path ca sa gaseasca `nids`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.metrics import classification_report  # noqa: E402

from nids.ml.modern.dataset import load_dataset, prepare_features  # noqa: E402
from nids.ml.modern.model import (  # noqa: E402
    DEFAULT_MODEL_PATH,
    ModernExpertModel,
    build_metrics,
)

DATA_DIR = (
    Path(__file__).resolve().parent.parent / "data" / "raw" / "cse-cic-ids2018" / "processed"
)


def main() -> None:
    train_df = load_dataset(DATA_DIR / "train.csv")
    test_df = load_dataset(DATA_DIR / "test.csv")

    x_train, y_train = prepare_features(train_df)
    x_test, y_test = prepare_features(test_df, encoded_columns=list(x_train.columns))

    # min_samples_leaf: FARA el, arborii cresc nelimitat pe 724k randuri -
    # rezultat masurat prima data: model de 1.18 GB (fata de 20.7 MB la cel
    # vechi, NSL-KDD/125k randuri), incarcat la fiecare instantiere
    # DashboardPanel in teste - suita completa de teste a urcat de la ~30s
    # la peste 5 minute (vezi BUGS.md). masuratori empirice pe acelasi set
    # de date, doar variind acest parametru:
    #   min_samples_leaf=5  -> 454 MB, acuratete 0.9439
    #   min_samples_leaf=20 -> 152 MB, acuratete 0.9442
    #   min_samples_leaf=50 ->  68 MB, acuratete 0.9435
    # acuratetea ramane practic neschimbata (arborii erau doar inutil de
    # adanci/mari, nu "mai precisi") - 50 alege dimensiunea cea mai mica
    # fara nicio pierdere reala de semnal
    model = RandomForestClassifier(
        n_estimators=200, min_samples_leaf=50, random_state=42, n_jobs=-1
    )
    model.fit(x_train, y_train)

    y_pred = model.predict(x_test)
    metrics = build_metrics(y_test, y_pred)
    print(f"acuratete pe test set (CSE-CIC-IDS2018): {metrics['accuracy']:.4f}")
    print(classification_report(y_test, y_pred, target_names=["normal", "atac"]))

    expert = ModernExpertModel(model, list(x_train.columns), metrics=metrics)
    expert.save()
    print(f"model salvat in {DEFAULT_MODEL_PATH}")


if __name__ == "__main__":
    main()
