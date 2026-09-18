import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from nids.ml.modern.model import ModernExpertModel, build_metrics


def _tiny_trained_model() -> tuple[RandomForestClassifier, list[str]]:
    x_train = pd.DataFrame(
        {
            "flow_duration": [10, 2000, 5, 3000],
            "totlen_fwd_pkts": [10, 5000, 0, 6000],
        }
    )
    y_train = [0, 1, 0, 1]

    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(x_train, y_train)
    return model, list(x_train.columns)


def test_modern_expert_model_save_and_load_round_trip(tmp_path):
    model, feature_columns = _tiny_trained_model()
    expert = ModernExpertModel(model, feature_columns)

    path = tmp_path / "modern_expert.joblib"
    expert.save(path)

    loaded = ModernExpertModel.load(path)

    x_test = pd.DataFrame({"flow_duration": [8], "totlen_fwd_pkts": [12]})
    assert loaded.predict(x_test) == expert.predict(x_test)


def test_modern_expert_model_predict_aligns_missing_columns_with_zero():
    model, feature_columns = _tiny_trained_model()
    expert = ModernExpertModel(model, feature_columns)

    x_test = pd.DataFrame({"flow_duration": [10]})  # lipseste totlen_fwd_pkts
    predictions = expert.predict(x_test)

    assert len(predictions) == 1


def test_metrics_defaults_to_none():
    model, feature_columns = _tiny_trained_model()
    expert = ModernExpertModel(model, feature_columns)

    assert expert.metrics is None


def test_metrics_round_trip_through_save_and_load(tmp_path):
    model, feature_columns = _tiny_trained_model()
    metrics = {"accuracy": 0.94, "normal_precision": 0.91}
    expert = ModernExpertModel(model, feature_columns, metrics=metrics)

    path = tmp_path / "modern_expert.joblib"
    expert.save(path)
    loaded = ModernExpertModel.load(path)

    assert loaded.metrics == metrics


def test_load_handles_payload_saved_before_metrics_field_existed(tmp_path):
    """backward compatibilitate: un model salvat inainte de introducerea
    campului metrics nu are cheia "metrics" deloc in payload"""
    model, feature_columns = _tiny_trained_model()
    path = tmp_path / "old_style.joblib"
    joblib.dump({"model": model, "feature_columns": feature_columns}, path)

    loaded = ModernExpertModel.load(path)

    assert loaded.metrics is None


# --- build_metrics ---


def test_build_metrics_returns_expected_keys():
    y_test = [0, 0, 1, 1]
    y_pred = [0, 1, 1, 1]

    metrics = build_metrics(y_test, y_pred)

    assert set(metrics) == {
        "accuracy",
        "normal_precision",
        "normal_recall",
        "attack_precision",
        "attack_recall",
    }
    assert metrics["accuracy"] == 0.75


def test_explain_groups_one_hot_protocol_columns_back_together():
    x_train = pd.DataFrame(
        {
            "flow_duration": [10, 2000],
            "protocol_tcp": [1, 0],
            "protocol_udp": [0, 1],
        }
    )
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(x_train, [0, 1])
    expert = ModernExpertModel(model, list(x_train.columns))

    contributions = expert.explain(x_train, raw_values={"protocol": "tcp", "flow_duration": 10})

    feature_names = [c.feature for c in contributions]
    assert "protocol" in feature_names
    assert "protocol_tcp" not in feature_names
    assert "protocol_udp" not in feature_names
