import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from nids.ml.modern.model import ModernExpertModel
from nids.ml.modern.predict import explain_flow, predict_flows
from tests.factories import make_cicflow_record


def _tiny_model() -> ModernExpertModel:
    x_train = pd.DataFrame({"flow_duration": [10, 5000], "totlen_fwd_pkts": [10, 6000]})
    model = RandomForestClassifier(n_estimators=5, random_state=42)
    model.fit(x_train, [0, 1])
    return ModernExpertModel(model, list(x_train.columns))


def test_predict_flows_empty_list_returns_empty():
    assert predict_flows(_tiny_model(), []) == []


def test_predict_flows_returns_one_prediction_per_record():
    predictions = predict_flows(
        _tiny_model(), [make_cicflow_record(), make_cicflow_record(flow_duration=5000)]
    )

    assert len(predictions) == 2
    assert all(p in (0, 1) for p in predictions)


def test_explain_flow_returns_feature_contributions():
    contributions = explain_flow(_tiny_model(), make_cicflow_record())

    assert len(contributions) > 0
    assert all(hasattr(c, "importance") for c in contributions)
