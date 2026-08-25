from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from nids.capture.packet_meta import PacketMeta
from nids.capture.pcap_reader import read_pcap
from nids.core.analysis import ScanUpdate, StreamAnalyzer, analyze_pcap
from nids.core.event import Event, Severity
from nids.core.hybrid_analysis import analyze_pcap_hybrid
from nids.core.inspect import ConnectionAssessment, assess_connection, assessment_from_json
from nids.core.live_hybrid import LiveHybridAnalyzer
from nids.core.ml_combination import BOTH_ATTACK_EVENT_TYPE
from nids.core.ml_settings import MlSettings
from nids.core.response_settings import ResponseSettings
from nids.ml.expert.model import ExpertModel
from nids.ml.features.nsl_kdd_style import NslKddStyleFeatures, extract_nsl_kdd_style_features
from nids.ml.local.learning import LocalModelManager
from nids.response.manager import BlockManager, BlockRuleError
from nids.signatures.sensitive_ports import SensitivePortTracker
from nids.storage.event_store import EventStore, StoredEvent
from nids.ui.live_capture_thread import LiveCaptureThread
from nids.ui.simulation_thread import SimulationThread
from nids.ui.widgets.connection_inspector import ConnectionInspectorDialog
from nids.ui.widgets.logs_panel import LogsPanel
from nids.ui.widgets.signatures_panel import SignaturesPanel
from nids.ui.widgets.traffic_chart import TrafficChartPanel
from nids.ui.widgets.traffic_panel import TrafficPanel

_SEVERITY_COLOR = {
    Severity.LOW: QColor("#4ec9b0"),
    Severity.MEDIUM: QColor("#dcdcaa"),
    Severity.HIGH: QColor("#f14c4c"),
}


@dataclass
class LocalModelStatus:
    is_learning: bool
    samples_collected: int
    min_training_samples: int


class DashboardPanel(QWidget):
    def __init__(
        self,
        block_manager: BlockManager,
        event_store: EventStore,
        signatures_panel: SignaturesPanel,
        traffic_panel: TrafficPanel,
        logs_panel: LogsPanel,
        ml_settings: MlSettings | None = None,
        response_settings: ResponseSettings | None = None,
    ) -> None:
        super().__init__()
        self._block_manager = block_manager
        self._event_store = event_store
        self._signatures_panel = signatures_panel
        self._traffic_panel = traffic_panel
        self._traffic_panel.analyze_requested.connect(self._on_traffic_analyze_requested)
        self._logs_panel = logs_panel
        self._logs_panel.analyze_requested.connect(self._on_log_analyze_requested)
        self._ml_settings = ml_settings if ml_settings is not None else MlSettings()
        self._response_settings = (
            response_settings if response_settings is not None else ResponseSettings()
        )

        self._status_label = QLabel("niciun fisier incarcat")

        self._load_button = QPushButton("Incarca PCAP...")
        self._load_button.clicked.connect(self._on_load_clicked)

        self._monitor_button = QPushButton("Porneste monitorizare")
        self._monitor_button.clicked.connect(self._on_monitor_clicked)

        self._simulate_button = QPushButton("Simuleaza port scan (safe)")
        self._simulate_button.setToolTip(
            "trimite conexiuni TCP scurte catre propriul IP din reteaua "
            "locala - safe, doar ca sa vezi sistemul reactionand live"
        )
        self._simulate_button.clicked.connect(self._on_simulate_clicked)

        top_bar = QHBoxLayout()
        top_bar.addWidget(self._load_button)
        top_bar.addWidget(self._monitor_button)
        top_bar.addWidget(self._simulate_button)
        top_bar.addWidget(self._status_label)
        top_bar.addStretch()

        self._traffic_chart = TrafficChartPanel()
        self._traffic_chart.setMinimumHeight(180)
        self._traffic_chart.setMaximumHeight(220)

        self._event_list = QListWidget()
        self._event_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._event_list.customContextMenuRequested.connect(self._on_event_context_menu)

        layout = QVBoxLayout(self)
        layout.addLayout(top_bar)
        layout.addWidget(self._traffic_chart)
        layout.addWidget(self._event_list)

        self._thread: LiveCaptureThread | None = None
        self._simulation_thread: SimulationThread | None = None
        self._stream_analyzer: StreamAnalyzer | None = None
        self._sensitive_tracker: SensitivePortTracker | None = None
        self._live_hybrid: LiveHybridAnalyzer | None = None
        self._packet_count = 0
        self._event_items: dict[tuple[str, str], QListWidgetItem] = {}
        self._all_packets: list[PacketMeta] = []
        self._inspector_dialogs: list[ConnectionInspectorDialog] = []
        self._expert_model = self._try_load_expert_model()

        self._ml_timer = QTimer(self)
        self._ml_timer.timeout.connect(self._on_ml_evaluation_tick)

    @staticmethod
    def _try_load_expert_model() -> ExpertModel | None:
        try:
            return ExpertModel.load()
        except FileNotFoundError:
            return None

    # --- status pentru panoul ML ---

    def expert_model_loaded(self) -> bool:
        return self._expert_model is not None

    def local_model_status(self) -> LocalModelStatus | None:
        if self._live_hybrid is None:
            return None
        manager = self._live_hybrid.local_manager
        return LocalModelStatus(
            is_learning=manager.is_learning,
            samples_collected=manager.samples_collected,
            min_training_samples=manager.min_training_samples,
        )

    # --- incarcare PCAP ---

    def _on_load_clicked(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Alege fisier PCAP", "", "Fisiere PCAP (*.pcap *.cap *.pcapng)"
        )
        if not path:
            return

        self._all_packets = read_pcap(path)
        self._traffic_panel.load_packets(self._all_packets)

        threshold = self._signatures_panel.threshold()
        window = self._signatures_panel.window_seconds()
        sensitive_ports = self._signatures_panel.sensitive_ports()
        if self._expert_model is not None:
            events = analyze_pcap_hybrid(
                path,
                self._expert_model,
                port_scan_threshold=threshold,
                port_scan_window=window,
                sensitive_ports=sensitive_ports,
            )
        else:
            events = analyze_pcap(
                path,
                port_scan_threshold=threshold,
                port_scan_window=window,
                sensitive_ports=sensitive_ports,
            )
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
        self._traffic_panel.clear()
        self._traffic_chart.clear()
        self._all_packets = []
        self._stream_analyzer = StreamAnalyzer(
            port_scan_threshold=self._signatures_panel.threshold(),
            window_seconds=self._signatures_panel.window_seconds(),
        )
        self._sensitive_tracker = SensitivePortTracker(self._signatures_panel.sensitive_ports())
        local_manager = LocalModelManager.load_or_new(
            min_training_samples=self._ml_settings.min_training_samples,
            retrain_every=self._ml_settings.retrain_every,
            max_buffer_size=self._ml_settings.max_buffer_size,
            contamination=self._ml_settings.contamination,
            n_estimators=self._ml_settings.n_estimators,
        )
        self._live_hybrid = LiveHybridAnalyzer(
            self._expert_model, local_manager, strict_reporting=self._ml_settings.strict_reporting
        )
        self._packet_count = 0

        self._thread = LiveCaptureThread()
        self._thread.packet_captured.connect(self._on_live_packet)
        self._thread.error.connect(self._on_live_error)
        self._thread.finished.connect(self._on_thread_finished)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()
        self._ml_timer.start(self._ml_settings.evaluation_interval_ms)

        self._monitor_button.setText("Opreste monitorizare")
        self._load_button.setEnabled(False)
        self._status_label.setText("monitorizare live pornita - 0 pachete")

    def stop_monitoring(self) -> None:
        """oprire asincrona (buton click) - doar semnaleaza thread-ul,
        nu asteapta. UI-ul se actualizeaza mai tarziu, cand vine
        semnalul finished (_on_thread_finished), care si salveaza
        modelul local daca a devenit activ"""
        if self._thread is not None:
            self._thread.stop()

    def shutdown(self) -> None:
        """oprire SINCRONA, pentru inchiderea aplicatiei - asteapta
        efectiv thread-ul sa se opreasca (cu timeout) si salveaza
        modelul local direct, in loc sa se bazeze pe semnalul finished.
        BUG REAL gasit de user: stop_monitoring() + inchiderea ferestrei
        lasa procesul sa moara inainte ca semnalul finished sa apuce sa
        fie procesat de event loop, deci _on_thread_finished (care face
        salvarea) nu rula niciodata - tot progresul modelului local
        (85+ conexiuni antrenate) se pierdea la fiecare inchidere"""
        if self._thread is not None:
            self._thread.stop()
            self._thread.wait(3000)

        if self._live_hybrid is not None and not self._live_hybrid.local_manager.is_learning:
            self._live_hybrid.local_manager.save()

    def _stop_monitoring(self) -> None:
        self._monitor_button.setEnabled(False)
        self._status_label.setText("se opreste monitorizarea...")
        self.stop_monitoring()

    def _on_live_packet(self, pkt) -> None:
        self._packet_count += 1
        self._status_label.setText(
            f"monitorizare live pornita - {self._packet_count} pachete"
        )
        self._traffic_panel.add_packet(pkt)
        self._traffic_chart.record_packet()
        self._all_packets.append(pkt)

        if self._live_hybrid is not None:
            self._live_hybrid.add_packet(pkt)

        if self._stream_analyzer is not None:
            update = self._stream_analyzer.process_packet(pkt)
            if update is not None:
                self._apply_scan_update(update)

        if self._sensitive_tracker is not None:
            sensitive_event = self._sensitive_tracker.process_packet(pkt)
            if sensitive_event is not None:
                self._append_events([sensitive_event])
                self._traffic_chart.record_event(sensitive_event.severity)

    def _on_live_error(self, message: str) -> None:
        self._status_label.setText(f"eroare captura live: {message}")

    # --- simulare ---

    def _on_simulate_clicked(self) -> None:
        if self._thread is None:
            self._status_label.setText(
                "porneste monitorizarea live intai, ca sa vezi simularea"
            )
            return

        self._simulate_button.setEnabled(False)
        self._status_label.setText("se ruleaza simularea de port scan...")

        self._simulation_thread = SimulationThread()
        self._simulation_thread.finished_ok.connect(self._on_simulation_finished)
        self._simulation_thread.error.connect(self._on_simulation_error)
        self._simulation_thread.finished.connect(self._simulation_thread.deleteLater)
        self._simulation_thread.start()

    def _on_simulation_finished(self, target_ip: str) -> None:
        self._simulate_button.setEnabled(True)
        self._status_label.setText(f"simulare rulata catre {target_ip}")
        self._simulation_thread = None

    def _on_simulation_error(self, message: str) -> None:
        self._simulate_button.setEnabled(True)
        self._status_label.setText(f"eroare simulare: {message}")
        self._simulation_thread = None

    def _on_ml_evaluation_tick(self) -> None:
        if self._live_hybrid is None:
            return
        events = self._live_hybrid.evaluate()
        for event in events:
            self._traffic_chart.record_event(event.severity)
            self._maybe_auto_block(event)
        self._append_events(events)

    def _maybe_auto_block(self, event: Event) -> None:
        """raspuns automat, opt-in (vezi CONTEXT-nids.md, "nivel de
        raspuns" - era in plan de la inceput, doar neimplementat). declanseaza
        DOAR pe BOTH_ATTACK (ambele modele de acord) - cel mai increzator
        caz, indiferent de strict_reporting (BOTH_ATTACK trece oricum de
        acel filtru). citit live, nu doar la pornirea monitorizarii - poate
        fi pornit/oprit din Raspuns in mijlocul unei sesiuni active.
        idempotent: block() nu face nimic daca IP-ul e deja blocat, iar
        verificarea is_blocked() de mai jos evita sa umplem Loguri cu
        acelasi "blocare automata" la fiecare conexiune noua de la acelasi IP"""
        if not self._response_settings.auto_block_enabled:
            return
        if event.event_type != BOTH_ATTACK_EVENT_TYPE:
            return
        if self._block_manager.is_blocked(event.source_ip):
            return

        try:
            self._block_manager.block(
                event.source_ip, reason=f"blocare automata: {event.description}"
            )
        except BlockRuleError as exc:
            self._status_label.setText(
                f"{exc} - blocare automata esuata, ruleaza aplicatia ca Administrator"
            )
            self._event_store.save(
                Event(
                    event_type="blocare automata esuata",
                    source_ip=event.source_ip,
                    severity=Severity.LOW,
                    description=f"{exc} - probabil lipsesc drepturile de Administrator",
                )
            )
            return

        self._event_store.save(
            Event(
                event_type="blocare automata",
                source_ip=event.source_ip,
                severity=Severity.LOW,
                description=(
                    f"blocat automat - ambele modele de acord: {event.description}"
                ),
                dest_ip=event.dest_ip,
                src_port=event.src_port,
                dest_port=event.dest_port,
                protocol=event.protocol,
                assessment_json=event.assessment_json,
            )
        )

    def _on_thread_finished(self) -> None:
        self._thread = None
        self._ml_timer.stop()
        if self._live_hybrid is not None and not self._live_hybrid.local_manager.is_learning:
            self._live_hybrid.local_manager.save()
        self._live_hybrid = None
        self._monitor_button.setText("Porneste monitorizare")
        self._monitor_button.setEnabled(True)
        self._load_button.setEnabled(True)

    # --- afisare ---

    def _apply_scan_update(self, update: ScanUpdate) -> None:
        if update.is_new:
            item = _make_event_item(update.event)
            self._event_list.addItem(item)
            self._event_items[update.pair] = item
            self._event_store.save(update.event)
            self._traffic_chart.record_event(update.event.severity)
        else:
            item = self._event_items.get(update.pair)
            if item is not None:
                item.setText(_format_event(update.event))
                item.setData(Qt.ItemDataRole.UserRole, update.event)

    def _append_events(self, events: list[Event]) -> None:
        for event in events:
            self._event_list.addItem(_make_event_item(event))
            self._event_store.save(event)

    # --- raspuns manual ---

    def _on_event_context_menu(self, position) -> None:
        item = self._event_list.itemAt(position)
        if item is None:
            return
        event: Event = item.data(Qt.ItemDataRole.UserRole)
        if event is None:
            return

        menu = QMenu(self)
        if self._block_manager.is_blocked(event.source_ip):
            action = menu.addAction(f"{event.source_ip} e deja blocat")
            action.setEnabled(False)
        else:
            action = menu.addAction(f"Blocheaza {event.source_ip} (temporar)")
            action.triggered.connect(lambda: self._block_event_source(event))
        menu.exec(self._event_list.viewport().mapToGlobal(position))

    # --- inspectie conexiune la cerere ---

    def _on_traffic_analyze_requested(self, pkt: PacketMeta) -> None:
        self._analyze_connection(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.protocol)

    def _on_log_analyze_requested(self, entry: StoredEvent) -> None:
        """analog cu analiza din Trafic, dar pornind de la un rand din
        Loguri. daca evenimentul are o "poza" salvata a analizei
        (assessment_json - vezi LiveHybridAnalyzer), o folosim direct,
        indiferent de sesiune - nu are nevoie de pachetele brute, care
        oricum nu mai exista dupa un restart. altfel (evenimente vechi,
        salvate inainte de aceasta functionalitate) incercam sa
        recalculam din traficul sesiunii curente, daca mai e disponibil"""
        if entry.assessment_json is not None:
            self._show_inspector(assessment_from_json(entry.assessment_json))
            return

        if entry.dest_ip is None:
            self._status_label.setText(
                "acest eveniment nu are o conexiune ML asociata (semnatura sau actiune manuala)"
            )
            return
        self._analyze_connection(
            entry.source_ip, entry.src_port, entry.dest_ip, entry.dest_port, entry.protocol
        )

    def _analyze_connection(
        self,
        src_ip: str,
        src_port: int | None,
        dst_ip: str,
        dst_port: int | None,
        protocol: str | None,
    ) -> None:
        if not self._all_packets:
            self._status_label.setText("nu exista trafic colectat de analizat")
            return

        records = extract_nsl_kdd_style_features(self._all_packets)
        record = _find_matching_connection(records, src_ip, src_port, dst_ip, dst_port, protocol)
        if record is None:
            self._status_label.setText(
                "nu s-a putut identifica conexiunea - probabil traficul brut nu mai e "
                "disponibil (alta sesiune sau pachete deja iesite din istoric)"
            )
            return

        local_manager = self._live_hybrid.local_manager if self._live_hybrid is not None else None
        assessment = assess_connection(record, self._expert_model, local_manager)
        self._show_inspector(assessment)

    def _show_inspector(self, assessment: ConnectionAssessment) -> None:
        dialog = ConnectionInspectorDialog(assessment, parent=self)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._inspector_dialogs.append(dialog)
        dialog.finished.connect(lambda: self._inspector_dialogs.remove(dialog))
        dialog.show()

    def _block_event_source(self, event: Event) -> None:
        try:
            self._block_manager.block(
                event.source_ip, reason=f"{event.event_type}: {event.description}"
            )
        except BlockRuleError as exc:
            # BUG REAL gasit de user: pe Windows, adaugarea regulii de
            # firewall (netsh) cere drepturi de Administrator - fara ele,
            # exceptia scapa pana aici daca nu e prinsa explicit. inainte
            # crapa toata aplicatia (traceback in terminal); acum arata
            # un mesaj clar si salveaza incercarea esuata in Loguri
            self._status_label.setText(
                f"{exc} - ruleaza aplicatia ca Administrator pentru blocare de firewall"
            )
            self._event_store.save(
                Event(
                    event_type="blocare esuata",
                    source_ip=event.source_ip,
                    severity=Severity.LOW,
                    description=f"{exc} - probabil lipsesc drepturile de Administrator",
                )
            )
            return

        self._event_store.save(
            Event(
                event_type="blocare manuala",
                source_ip=event.source_ip,
                severity=Severity.LOW,
                description=f"blocat manual, motiv: {event.event_type} - {event.description}",
                # mostenim identitatea conexiunii (+ analiza ML deja
                # calculata, daca exista) de la evenimentul care a
                # declansat blocarea - altfel randul de "blocare manuala"
                # din Loguri nu avea NIMIC de-al lui, desi originea lui
                # ESTE o conexiune analizata (userul a semnalat ca vrea
                # sa poata analiza si de aici, nu doar evenimentul original)
                dest_ip=event.dest_ip,
                src_port=event.src_port,
                dest_port=event.dest_port,
                protocol=event.protocol,
                assessment_json=event.assessment_json,
            )
        )


def _find_matching_connection(
    records: list[NslKddStyleFeatures],
    src_ip: str,
    src_port: int | None,
    dst_ip: str,
    dst_port: int | None,
    protocol: str | None,
) -> NslKddStyleFeatures | None:
    """gaseste conexiunea cu aceasta identitate (IP-uri, porturi,
    protocol) - extract_connections normalizeaza directia (originea e
    cine a trimis primul pachet), deci identitatea ceruta poate fi fie
    in directia "src->dst" a recordului, fie in cea inversa (un raspuns).
    protocol=None (posibil pentru evenimente vechi, dinainte de a salva
    acest camp) inseamna ca nu se verifica protocolul"""
    for record in records:
        forward = (record.src_ip, record.src_port, record.dst_ip, record.dst_port)
        backward = (record.dst_ip, record.dst_port, record.src_ip, record.src_port)
        pair = (src_ip, src_port, dst_ip, dst_port)
        if pair not in (forward, backward):
            continue
        if protocol is not None and record.protocol_type != protocol:
            continue
        return record
    return None


def _format_event(event: Event) -> str:
    return f"[{event.severity.value}] {event.event_type} - {event.source_ip} - {event.description}"


def _make_event_item(event: Event) -> QListWidgetItem:
    item = QListWidgetItem(_format_event(event))
    item.setForeground(_SEVERITY_COLOR[event.severity])
    item.setData(Qt.ItemDataRole.UserRole, event)
    return item
