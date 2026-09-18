from pathlib import Path

import pandas as pd
from PySide6.QtWidgets import QApplication
from sklearn.ensemble import RandomForestClassifier

from nids.capture.packet_meta import PacketMeta
from nids.ml.modern.model import ModernExpertModel
from nids.response.manager import BlockManager
from nids.storage.event_store import EventStore
from nids.ui.widgets.dashboard_panel import DashboardPanel, _find_matching_flow
from nids.ui.widgets.logs_panel import LogsPanel
from nids.ui.widgets.signatures_panel import SignaturesPanel
from nids.ui.widgets.traffic_panel import TrafficPanel
from tests.factories import make_cicflow_record


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _make_panel(tmp_path: Path) -> DashboardPanel:
    event_store = EventStore(tmp_path / "test.db")
    return DashboardPanel(
        BlockManager(add_rule=lambda ip: None, remove_rule=lambda ip: None),
        event_store,
        SignaturesPanel(),
        TrafficPanel(),
        LogsPanel(event_store),
    )


def _packet(src_ip="10.0.0.1", src_port=5000, dst_ip="10.0.0.2", dst_port=80, ts=0.0) -> PacketMeta:
    return PacketMeta(
        timestamp=ts, src_ip=src_ip, dst_ip=dst_ip, protocol="tcp", length=100,
        src_port=src_port, dst_port=dst_port,
    )


def _tiny_modern_model() -> ModernExpertModel:
    x_train = pd.DataFrame({"flow_duration": [10, 5000], "totlen_fwd_pkts": [10, 6000]})
    model = RandomForestClassifier(n_estimators=5, random_state=42)
    model.fit(x_train, [0, 1])
    return ModernExpertModel(model, list(x_train.columns))


# --- _find_matching_flow ---


def test_find_matching_flow_matches_either_direction():
    flows = [make_cicflow_record(src_ip="10.0.0.1", src_port=5000, dst_ip="10.0.0.2", dst_port=80)]

    match = _find_matching_flow(flows, "10.0.0.2", 80, "10.0.0.1", 5000, "tcp")

    assert match is flows[0]


def test_find_matching_flow_returns_none_when_no_match():
    flows = [make_cicflow_record(src_ip="10.0.0.1", src_port=5000, dst_ip="10.0.0.2", dst_port=80)]

    match = _find_matching_flow(flows, "10.0.0.9", 1234, "10.0.0.8", 80, "tcp")

    assert match is None


def test_find_matching_flow_respects_protocol_when_given():
    flows = [make_cicflow_record(src_ip="10.0.0.1", src_port=5000, dst_ip="10.0.0.2", dst_port=80, protocol="tcp")]

    match = _find_matching_flow(flows, "10.0.0.1", 5000, "10.0.0.2", 80, "udp")

    assert match is None


# --- DashboardPanel._assess_modern_connection ---


def test_assess_modern_connection_returns_none_without_model(tmp_path):
    _app()
    panel = _make_panel(tmp_path)
    # setat explicit la None - un model real (data/models/modern_expert_random_forest.joblib)
    # poate exista deja pe disc daca a fost antrenat, __init__ l-ar fi
    # incarcat automat - testul trebuie sa verifice ramura "fara model"
    # indiferent de ce se intampla a fi pe disc-ul curent
    panel._modern_expert_model = None
    panel._all_packets = [_packet()]

    result = panel._assess_modern_connection("10.0.0.1", 5000, "10.0.0.2", 80, "tcp")

    assert result is None


def test_assess_modern_connection_returns_none_when_no_matching_flow(tmp_path):
    _app()
    panel = _make_panel(tmp_path)
    panel._modern_expert_model = _tiny_modern_model()
    panel._all_packets = [_packet(src_ip="10.0.0.9", dst_ip="10.0.0.8")]

    result = panel._assess_modern_connection("10.0.0.1", 5000, "10.0.0.2", 80, "tcp")

    assert result is None


def test_assess_modern_connection_returns_assessment_when_model_and_flow_exist(tmp_path):
    _app()
    panel = _make_panel(tmp_path)
    panel._modern_expert_model = _tiny_modern_model()
    panel._all_packets = [_packet(ts=0.0), _packet(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=5000, ts=0.1)]

    result = panel._assess_modern_connection("10.0.0.1", 5000, "10.0.0.2", 80, "tcp")

    assert result is not None
    assert result.expert_prediction in (0, 1)


def test_modern_expert_model_loaded_reflects_state(tmp_path):
    _app()
    panel = _make_panel(tmp_path)

    panel._modern_expert_model = None
    assert panel.modern_expert_model_loaded() is False

    panel._modern_expert_model = _tiny_modern_model()
    assert panel.modern_expert_model_loaded() is True


# --- _model_comparison_counts ---


class _FakeAnalyzer:
    def __init__(self, agreement_counts):
        from nids.core.ml_combination import Agreement

        self.agreement_counts = {getattr(Agreement, k): v for k, v in agreement_counts.items()}


def test_model_comparison_counts_returns_empty_dicts_without_analyzers(tmp_path):
    _app()
    panel = _make_panel(tmp_path)
    panel._live_hybrid = None
    panel._modern_live_hybrid = None

    old_counts, modern_counts = panel._model_comparison_counts()

    assert old_counts == {}
    assert modern_counts == {}


def test_model_comparison_counts_uses_short_labels_from_both_analyzers(tmp_path):
    _app()
    panel = _make_panel(tmp_path)
    panel._live_hybrid = _FakeAnalyzer({"BOTH_ATTACK": 3, "EXPERT_ONLY": 1})
    panel._modern_live_hybrid = _FakeAnalyzer({"BOTH_ATTACK": 5})

    old_counts, modern_counts = panel._model_comparison_counts()

    assert old_counts == {"ambele: atac": 3, "doar expert": 1}
    assert modern_counts == {"ambele: atac": 5}


# --- modern_expert_metrics ---


def test_modern_expert_metrics_returns_none_without_model(tmp_path):
    _app()
    panel = _make_panel(tmp_path)
    panel._modern_expert_model = None

    assert panel.modern_expert_metrics() is None


def test_modern_expert_metrics_returns_the_model_metrics(tmp_path):
    _app()
    panel = _make_panel(tmp_path)
    x_train = pd.DataFrame({"flow_duration": [10, 5000]})
    sk_model = RandomForestClassifier(n_estimators=5, random_state=42).fit(x_train, [0, 1])
    panel._modern_expert_model = ModernExpertModel(
        sk_model, list(x_train.columns), metrics={"accuracy": 0.9}
    )

    assert panel.modern_expert_metrics() == {"accuracy": 0.9}
