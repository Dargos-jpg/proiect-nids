import time

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QApplication, QMessageBox

from nids.honeypot.listener import HoneypotHit
from nids.honeypot.training_data import HoneypotTrainingStore
from nids.ml.expert.retrain import MIN_HONEYPOT_SAMPLES, RetrainResult
from nids.storage.event_store import EventStore
from nids.ui.widgets.honeypot_panel import HoneypotPanel


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _panel(tmp_path) -> HoneypotPanel:
    """orice test care declanseaza un hit trebuie sa foloseasca un
    training_store izolat (tmp_path) - altfel HoneypotPanel ar scrie in
    fisierul real data/models/honeypot_training_sessions.joblib din
    proiect la fiecare rulare a testelor"""
    training_store = HoneypotTrainingStore(tmp_path / "honeypot_training.joblib")
    return HoneypotPanel(EventStore(tmp_path / "test.db"), training_store=training_store)


def _wait_until(app: QApplication, condition, timeout: float = 3.0) -> None:
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert condition(), "conditia nu a fost indeplinita in timp util"


def test_ports_parses_comma_separated_list(tmp_path):
    _app()
    panel = _panel(tmp_path)

    panel._ports_edit.setText("2222, 8080,  3306")

    assert panel.ports() == [2222, 8080, 3306]


def test_ports_ignores_invalid_tokens(tmp_path):
    _app()
    panel = _panel(tmp_path)

    panel._ports_edit.setText("2222, abc, , 70000, 8080")

    assert panel.ports() == [2222, 8080]


def test_ports_empty_text_returns_empty_list(tmp_path):
    _app()
    panel = _panel(tmp_path)

    panel._ports_edit.setText("")

    assert panel.ports() == []


def test_start_with_no_valid_ports_shows_message_and_does_not_start(tmp_path):
    _app()
    panel = _panel(tmp_path)
    panel._ports_edit.setText("")

    panel._on_toggle_clicked()

    assert "port valid" in panel._status_label.text()
    assert panel._thread is None


def test_full_lifecycle_logs_hit_and_stops_cleanly(tmp_path, monkeypatch):
    """porneste (thread real, run_honeypot inlocuit) -> primeste un hit
    -> verifica ca ajunge in EventStore -> opreste curat"""
    app = _app()

    def fake_run_honeypot(ports, on_hit, on_bind_error, stop_event):
        on_hit(HoneypotHit(src_ip="1.2.3.4", src_port=1111, dst_port=2222, received_preview=""))
        while not stop_event.is_set():
            time.sleep(0.02)

    monkeypatch.setattr("nids.ui.honeypot_thread.run_honeypot", fake_run_honeypot)

    panel = _panel(tmp_path)
    event_store = panel._event_store
    panel._ports_edit.setText("2222")

    panel._on_toggle_clicked()
    _wait_until(app, lambda: len(event_store.recent()) == 1)

    logged = event_store.recent()[0]
    assert logged.event_type == "conexiune la honeypot"
    assert logged.source_ip == "1.2.3.4"
    assert panel._toggle_button.text() == "Opreste honeypot"
    assert not panel._ports_edit.isEnabled()

    panel._on_toggle_clicked()
    _wait_until(app, lambda: panel._thread is None)

    assert panel._toggle_button.text() == "Porneste honeypot"
    assert panel._ports_edit.isEnabled()
    assert panel._status_label.text() == "honeypot oprit"


def test_bind_error_message_survives_thread_finishing(tmp_path, monkeypatch):
    """regresie: daca toate porturile esueaza la bind, thread-ul se
    termina aproape imediat - mesajul de eroare nu trebuie suprascris de
    genericul "honeypot oprit" """
    app = _app()

    def fake_run_honeypot(ports, on_hit, on_bind_error, stop_event):
        on_bind_error(2222, "port deja folosit")

    monkeypatch.setattr("nids.ui.honeypot_thread.run_honeypot", fake_run_honeypot)

    panel = _panel(tmp_path)
    panel._ports_edit.setText("2222")

    panel._on_toggle_clicked()
    _wait_until(app, lambda: panel._thread is None)

    assert "port deja folosit" in panel._status_label.text()


def _hit(i: int = 0) -> HoneypotHit:
    return HoneypotHit(src_ip=f"10.0.0.{i}", src_port=40000 + i, dst_port=2222, received_preview="")


class _FakeRetrainThread(QThread):
    """inlocuieste RetrainThread in teste de UI - antrenarea reala (doua
    RandomForest-uri pe NSL-KDD) e testata separat, in test_expert_retrain.py;
    aici verificam doar cablarea semnal/status din HoneypotPanel"""

    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, honeypot_packets, parent=None) -> None:
        super().__init__(parent)
        self._honeypot_packets = honeypot_packets

    def run(self) -> None:
        self.succeeded.emit(
            RetrainResult(
                honeypot_connections_used=MIN_HONEYPOT_SAMPLES,
                accuracy_before=0.5,
                accuracy_after=0.9,
                model_saved=True,
            )
        )


def test_retrain_button_disabled_below_threshold(tmp_path):
    _app()
    panel = _panel(tmp_path)

    assert not panel._retrain_button.isEnabled()
    assert str(MIN_HONEYPOT_SAMPLES) in panel._retrain_status_label.text()


def test_retrain_button_enables_after_enough_hits(tmp_path):
    _app()
    panel = _panel(tmp_path)

    for i in range(MIN_HONEYPOT_SAMPLES):
        panel._on_hit(_hit(i))

    assert panel._retrain_button.isEnabled()


def test_declining_confirmation_does_not_start_retraining(tmp_path, monkeypatch):
    app = _app()
    panel = _panel(tmp_path)
    for i in range(MIN_HONEYPOT_SAMPLES):
        panel._on_hit(_hit(i))
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    monkeypatch.setattr("nids.ui.widgets.honeypot_panel.RetrainThread", _FakeRetrainThread)

    panel._on_retrain_clicked()
    app.processEvents()

    assert panel._retrain_thread is None
    assert "reantrenat" not in panel._retrain_status_label.text()


def test_confirming_retraining_shows_accuracy_result(tmp_path, monkeypatch):
    app = _app()
    panel = _panel(tmp_path)
    for i in range(MIN_HONEYPOT_SAMPLES):
        panel._on_hit(_hit(i))
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr("nids.ui.widgets.honeypot_panel.RetrainThread", _FakeRetrainThread)

    panel._on_retrain_clicked()
    _wait_until(app, lambda: "0.5000" in panel._retrain_status_label.text())

    assert "0.9000" in panel._retrain_status_label.text()
    assert panel._retrain_thread is None


class _FakeRegressingRetrainThread(QThread):
    """simuleaza cazul in care noul model iese mai slab - regresie pentru
    gaura de siguranta semnalata de user (vezi NOTES.md/BUGS.md)"""

    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, honeypot_packets, parent=None) -> None:
        super().__init__(parent)

    def run(self) -> None:
        self.succeeded.emit(
            RetrainResult(
                honeypot_connections_used=MIN_HONEYPOT_SAMPLES,
                accuracy_before=0.9,
                accuracy_after=0.5,
                model_saved=False,
            )
        )


def test_retraining_with_worse_accuracy_reports_model_not_changed(tmp_path, monkeypatch):
    app = _app()
    panel = _panel(tmp_path)
    for i in range(MIN_HONEYPOT_SAMPLES):
        panel._on_hit(_hit(i))
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr("nids.ui.widgets.honeypot_panel.RetrainThread", _FakeRegressingRetrainThread)

    panel._on_retrain_clicked()
    _wait_until(app, lambda: "NU a fost schimbat" in panel._retrain_status_label.text())

    assert "0.9000" in panel._retrain_status_label.text()
    assert "0.5000" in panel._retrain_status_label.text()
