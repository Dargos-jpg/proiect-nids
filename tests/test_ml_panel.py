from PySide6.QtWidgets import QApplication

from nids.core.ml_settings import MlSettings
from nids.response.manager import BlockManager
from nids.storage.event_store import EventStore
from nids.ui.widgets.dashboard_panel import DashboardPanel, LocalModelStatus
from nids.ui.widgets.logs_panel import LogsPanel
from nids.ui.widgets.ml_panel import MlPanel
from nids.ui.widgets.signatures_panel import SignaturesPanel
from nids.ui.widgets.traffic_panel import TrafficPanel


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _make_dashboard(tmp_path) -> DashboardPanel:
    event_store = EventStore(tmp_path / "test.db")
    return DashboardPanel(
        BlockManager(add_rule=lambda ip: None, remove_rule=lambda ip: None),
        event_store,
        SignaturesPanel(),
        TrafficPanel(),
        LogsPanel(event_store),
    )


def test_shows_expert_missing_when_not_loaded(tmp_path, monkeypatch):
    _app()
    dashboard = _make_dashboard(tmp_path)
    monkeypatch.setattr(dashboard, "expert_model_loaded", lambda: False)
    monkeypatch.setattr(dashboard, "local_model_status", lambda: None)

    panel = MlPanel(dashboard, MlSettings())

    assert "LIPSA" in panel._expert_label.text()
    assert "nu ruleaza" in panel._local_label.text()


def test_shows_expert_loaded(tmp_path, monkeypatch):
    _app()
    dashboard = _make_dashboard(tmp_path)
    monkeypatch.setattr(dashboard, "expert_model_loaded", lambda: True)
    monkeypatch.setattr(dashboard, "local_model_status", lambda: None)

    panel = MlPanel(dashboard, MlSettings())

    assert "incarcat" in panel._expert_label.text()


def test_shows_local_learning_progress(tmp_path, monkeypatch):
    _app()
    dashboard = _make_dashboard(tmp_path)
    monkeypatch.setattr(dashboard, "expert_model_loaded", lambda: True)
    monkeypatch.setattr(
        dashboard,
        "local_model_status",
        lambda: LocalModelStatus(is_learning=True, samples_collected=7, min_training_samples=50),
    )

    panel = MlPanel(dashboard, MlSettings())

    assert "7/50" in panel._local_label.text()


def test_shows_local_active(tmp_path, monkeypatch):
    _app()
    dashboard = _make_dashboard(tmp_path)
    monkeypatch.setattr(dashboard, "expert_model_loaded", lambda: True)
    monkeypatch.setattr(
        dashboard,
        "local_model_status",
        lambda: LocalModelStatus(is_learning=False, samples_collected=50, min_training_samples=50),
    )

    panel = MlPanel(dashboard, MlSettings())

    assert "activ" in panel._local_label.text()


# --- setari ---


def test_panel_prefills_controls_from_existing_settings(tmp_path):
    _app()
    dashboard = _make_dashboard(tmp_path)
    settings = MlSettings(min_training_samples=77, retrain_every=13, max_buffer_size=999)

    panel = MlPanel(dashboard, settings)

    assert panel._contamination_spin.isEnabled() is False  # contamination=None -> automat


def test_changing_min_training_samples_updates_settings(tmp_path):
    _app()
    dashboard = _make_dashboard(tmp_path)
    settings = MlSettings()
    panel = MlPanel(dashboard, settings)

    panel._on_min_training_samples_changed(80)

    assert settings.min_training_samples == 80


def test_changing_retrain_every_updates_settings(tmp_path):
    _app()
    dashboard = _make_dashboard(tmp_path)
    settings = MlSettings()
    panel = MlPanel(dashboard, settings)

    panel._on_retrain_every_changed(10)

    assert settings.retrain_every == 10


def test_changing_max_buffer_size_updates_settings(tmp_path):
    _app()
    dashboard = _make_dashboard(tmp_path)
    settings = MlSettings()
    panel = MlPanel(dashboard, settings)

    panel._on_max_buffer_size_changed(500)

    assert settings.max_buffer_size == 500


def test_unchecking_auto_contamination_enables_manual_value(tmp_path):
    _app()
    dashboard = _make_dashboard(tmp_path)
    settings = MlSettings()
    panel = MlPanel(dashboard, settings)

    panel._auto_contamination.setChecked(False)

    assert panel._contamination_spin.isEnabled() is True
    assert settings.contamination == panel._contamination_spin.value()


def test_checking_auto_contamination_sets_none(tmp_path):
    _app()
    dashboard = _make_dashboard(tmp_path)
    settings = MlSettings(contamination=0.2)
    panel = MlPanel(dashboard, settings)
    panel._auto_contamination.setChecked(False)

    panel._auto_contamination.setChecked(True)

    assert panel._contamination_spin.isEnabled() is False
    assert settings.contamination is None


def test_changing_contamination_spin_updates_settings_when_manual(tmp_path):
    _app()
    dashboard = _make_dashboard(tmp_path)
    settings = MlSettings()
    panel = MlPanel(dashboard, settings)
    panel._auto_contamination.setChecked(False)

    panel._contamination_spin.setValue(0.33)

    assert settings.contamination == 0.33


def test_changing_n_estimators_updates_settings(tmp_path):
    _app()
    dashboard = _make_dashboard(tmp_path)
    settings = MlSettings()
    panel = MlPanel(dashboard, settings)

    panel._on_n_estimators_changed(200)

    assert settings.n_estimators == 200


def test_toggling_strict_reporting_updates_settings(tmp_path):
    _app()
    dashboard = _make_dashboard(tmp_path)
    settings = MlSettings()
    panel = MlPanel(dashboard, settings)

    panel._on_strict_reporting_toggled(True)

    assert settings.strict_reporting is True


def test_changing_evaluation_interval_converts_seconds_to_ms(tmp_path):
    _app()
    dashboard = _make_dashboard(tmp_path)
    settings = MlSettings()
    panel = MlPanel(dashboard, settings)

    panel._on_evaluation_interval_changed(12)

    assert settings.evaluation_interval_ms == 12_000
