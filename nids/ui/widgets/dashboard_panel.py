from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from nids.core.analysis import ScanUpdate, StreamAnalyzer, analyze_pcap
from nids.core.event import Event, Severity
from nids.core.hybrid_analysis import analyze_pcap_hybrid
from nids.ml.expert.model import ExpertModel
from nids.ui.live_capture_thread import LiveCaptureThread

_SEVERITY_COLOR = {
    Severity.LOW: QColor("#4ec9b0"),
    Severity.MEDIUM: QColor("#dcdcaa"),
    Severity.HIGH: QColor("#f14c4c"),
}


class DashboardPanel(QWidget):
    def __init__(self) -> None:
        super().__init__()

        self._status_label = QLabel("niciun fisier incarcat")

        self._load_button = QPushButton("Incarca PCAP...")
        self._load_button.clicked.connect(self._on_load_clicked)

        self._monitor_button = QPushButton("Porneste monitorizare")
        self._monitor_button.clicked.connect(self._on_monitor_clicked)

        top_bar = QHBoxLayout()
        top_bar.addWidget(self._load_button)
        top_bar.addWidget(self._monitor_button)
        top_bar.addWidget(self._status_label)
        top_bar.addStretch()

        self._event_list = QListWidget()

        layout = QVBoxLayout(self)
        layout.addLayout(top_bar)
        layout.addWidget(self._event_list)

        self._thread: LiveCaptureThread | None = None
        self._stream_analyzer: StreamAnalyzer | None = None
        self._packet_count = 0
        self._event_items: dict[tuple[str, str], QListWidgetItem] = {}
        self._expert_model = self._try_load_expert_model()

    @staticmethod
    def _try_load_expert_model() -> ExpertModel | None:
        try:
            return ExpertModel.load()
        except FileNotFoundError:
            return None

    # --- incarcare PCAP ---

    def _on_load_clicked(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Alege fisier PCAP", "", "Fisiere PCAP (*.pcap *.cap *.pcapng)"
        )
        if not path:
            return

        if self._expert_model is not None:
            events = analyze_pcap_hybrid(path, self._expert_model)
        else:
            events = analyze_pcap(path)
        self._show_events(path, events)

    def _show_events(self, path: str, events: list[Event]) -> None:
        self._event_list.clear()
        self._append_events(events)

        if events:
            self._status_label.setText(f"{path} - {len(events)} eveniment(e)")
        else:
            self._status_label.setText(f"{path} - niciun eveniment detectat")

    # --- monitorizare live ---

    def _on_monitor_clicked(self) -> None:
        if self._thread is None:
            self._start_monitoring()
        else:
            self._stop_monitoring()

    def _start_monitoring(self) -> None:
        self._event_list.clear()
        self._event_items = {}
        self._stream_analyzer = StreamAnalyzer()
        self._packet_count = 0

        self._thread = LiveCaptureThread()
        self._thread.packet_captured.connect(self._on_live_packet)
        self._thread.error.connect(self._on_live_error)
        self._thread.finished.connect(self._on_thread_finished)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()

        self._monitor_button.setText("Opreste monitorizare")
        self._load_button.setEnabled(False)
        self._status_label.setText("monitorizare live pornita - 0 pachete")

    def stop_monitoring(self) -> None:
        """oprire cerute din exterior (ex: la inchiderea ferestrei) -
        doar semnaleaza thread-ul, nu asteapta sa se opreasca"""
        if self._thread is not None:
            self._thread.stop()

    def _stop_monitoring(self) -> None:
        self._monitor_button.setEnabled(False)
        self._status_label.setText("se opreste monitorizarea...")
        self.stop_monitoring()

    def _on_live_packet(self, pkt) -> None:
        self._packet_count += 1
        self._status_label.setText(
            f"monitorizare live pornita - {self._packet_count} pachete"
        )

        if self._stream_analyzer is None:
            return
        update = self._stream_analyzer.process_packet(pkt)
        if update is not None:
            self._apply_scan_update(update)

    def _on_live_error(self, message: str) -> None:
        self._status_label.setText(f"eroare captura live: {message}")

    def _on_thread_finished(self) -> None:
        self._thread = None
        self._monitor_button.setText("Porneste monitorizare")
        self._monitor_button.setEnabled(True)
        self._load_button.setEnabled(True)

    # --- afisare ---

    def _apply_scan_update(self, update: ScanUpdate) -> None:
        if update.is_new:
            item = QListWidgetItem(_format_event(update.event))
            item.setForeground(_SEVERITY_COLOR[update.event.severity])
            self._event_list.addItem(item)
            self._event_items[update.pair] = item
        else:
            item = self._event_items.get(update.pair)
            if item is not None:
                item.setText(_format_event(update.event))

    def _append_events(self, events: list[Event]) -> None:
        for event in events:
            item = QListWidgetItem(_format_event(event))
            item.setForeground(_SEVERITY_COLOR[event.severity])
            self._event_list.addItem(item)


def _format_event(event: Event) -> str:
    return f"[{event.severity.value}] {event.event_type} - {event.source_ip} - {event.description}"
