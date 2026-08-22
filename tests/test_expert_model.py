import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from nids.ml.expert.model import ExpertModel


def _tiny_trained_model() -> tuple[RandomForestClassifier, list[str]]:
    x_train = pd.DataFrame(
        {
            "src_bytes": [10, 2000, 5, 3000],
            "dst_bytes": [10, 5000, 0, 6000],
        }
    )
    y_train = [0, 1, 0, 1]

    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(x_train, y_train)
    return model, list(x_train.columns)


def test_expert_model_save_and_load_round_trip(tmp_path):
    model, feature_columns = _tiny_trained_model()
    expert = ExpertModel(model, feature_columns)

    path = tmp_path / "expert_model.joblib"
    expert.save(path)

    loaded = ExpertModel.load(path)

    x_test = pd.DataFrame({"src_bytes": [8], "dst_bytes": [12]})
    assert loaded.predict(x_test) == expert.predict(x_test)


def test_expert_model_predict_aligns_missing_columns_with_zero():
    model, feature_columns = _tiny_trained_model()
    expert = ExpertModel(model, feature_columns)

    # lipseste "dst_bytes" complet din input - trebuie completat cu 0,
    # nu sa pice cu eroare
    x_test = pd.DataFrame({"src_bytes": [10]})
    predictions = expert.predict(x_test)

    assert len(predictions) == 1
