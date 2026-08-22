from __future__ import annotations

import sys
from pathlib import Path

# scripturile ruleaza direct (nu ca modul python -m), asa ca radacina
# proiectului trebuie adaugata manual pe sys.path ca sa gaseasca `nids`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.metrics import accuracy_score, classification_report  # noqa: E402

from nids.ml.expert.model import DEFAULT_MODEL_PATH, ExpertModel  # noqa: E402
from nids.ml.expert.nsl_kdd import load_dataset, prepare_features  # noqa: E402

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "raw" / "nsl-kdd"


def main() -> None:
    train_df = load_dataset(DATA_DIR / "KDDTrain+.txt")
    test_df = load_dataset(DATA_DIR / "KDDTest+.txt")

    x_train, y_train = prepare_features(train_df)
    x_test, y_test = prepare_features(test_df, encoded_columns=list(x_train.columns))

    model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    model.fit(x_train, y_train)

    y_pred = model.predict(x_test)
    print(f"acuratete pe test set: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred, target_names=["normal", "atac"]))

    expert = ExpertModel(model, list(x_train.columns))
    expert.save()
    print(f"model salvat in {DEFAULT_MODEL_PATH}")


if __name__ == "__main__":
    main()
