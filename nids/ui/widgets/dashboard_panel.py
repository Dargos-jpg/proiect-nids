from __future__ import annotations

import json
from collections import deque
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
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from nids.capture.arp_meta import ArpFrame
from nids.capture.dns_meta import DnsQuery
from nids.capture.packet_meta import PacketMeta
from nids.capture.pcap_reader import read_pcap
from nids.capture.payload_meta import PayloadSample, read_pcap_payload_samples
from nids.core.analysis import ScanUpdate, StreamAnalyzer, analyze_pcap
from nids.core.event import Event, Severity
from nids.core.hybrid_analysis import analyze_pcap_hybrid
from nids.core.inspect import ConnectionAssessment, assess_connection, assessment_from_json
from nids.core.live_hybrid import LiveHybridAnalyzer
from nids.core.ml_combination import BOTH_ATTACK_EVENT_TYPE, Agreement
from nids.core.ml_settings import MlSettings
from nids.core.response_settings import ResponseSettings
from nids.ml.expert.model import ExpertModel
from nids.ml.features.cicflow_style import CicFlowFeatures, extract_cicflow_features
from nids.ml.features.nsl_kdd_style import NslKddStyleFeatures, extract_nsl_kdd_style_features
from nids.ml.local.learning import LocalModelManager
from nids.ml.modern.hybrid_analysis import analyze_pcap_modern_hybrid
from nids.ml.modern.inspect import ModernAssessment, assess_modern, modern_assessment_from_json
from nids.ml.modern.learning import ModernLocalModelManager
from nids.ml.modern.live_hybrid import ModernLiveHybridAnalyzer
from nids.ml.modern.model import ModernExpertModel
from nids.response.manager import BlockManager, BlockRuleError
from nids.signatures.arp_spoofing import ArpSpoofTracker
from nids.signatures.brute_force import BruteForceTracker
from nids.signatures.dns_tunneling import DnsTunnelTracker
from nids.signatures.payload_signatures import PayloadSignatureTracker
from nids.signatures.sensitive_ports import SensitivePortTracker
from nids.storage.event_store import EventStore, StoredEvent
from nids.ui.live_capture_thread import LiveCaptureThread
from nids.ui.simulation_thread import SimulationThread
from nids.ui.widgets.connection_inspector import ConnectionInspectorDialog
from nids.ui.widgets.forensics_panel import ConnectionTimelineDialog, ForensicsPanel, packets_for_connection
from nids.ui.widgets.logs_panel import LogsPanel
from nids.ui.widgets.signatures_panel import SignaturesPanel
from nids.ui.widgets.traffic_chart import TrafficChartPanel
from nids.ui.widgets.traffic_panel import TrafficPanel

_SEVERITY_COLOR = {
    Severity.LOW: QColor("#4ec9b0"),
    Severity.MEDIUM: QColor("#dcdcaa"),
    Severity.HIGH: QColor("#f14c4c"),
}

# etichete scurte pentru graficul de comparatie vechi-vs-modern
# (TrafficChartPanel) - valorile Agreement sunt fraze intregi, prea lungi
# pentru axa unui bar chart
_AGREEMENT_SHORT_LABELS = {
    Agreement.BOTH_ATTACK: "ambele: atac",
    Agreement.BOTH_NORMAL: "ambele: normal",
    Agreement.EXPERT_ONLY: "doar expert",
    Agreement.LOCAL_ONLY: "doar local",
    Agreement.LOCAL_LEARNING: "local invata",
}

# BUG REAL notat de user (BUGS.md, fix-ul de lag din monitorizarea live):
# spre deosebire de bufferul intern al analizoarelor (deja plafonat la
# 20_000, vezi LiveHybridAnalyzer/ModernLiveHybridAnalyzer), lista asta
# ramasese neplafonata - creste nelimitat pe durata unei sesiuni live,
# facand un singur click pe "Analizeaza aceasta conexiune"/"Reconstruieste
# conexiunea" din ce in ce mai lent (reproceseaza TOATA lista) si consumand
# memorie tot mai multa. plafon mai mare decat bufferul analizoarelor
# (foloseste si pentru forensics/analiza directa din Trafic pe conexiuni
# INCA neevaluate, nu doar pentru evaluare periodica) - de la Faza 7
# (persistarea assessment_json), evenimentele deja raportate NU mai
# depind deloc de aceasta lista, deci un plafon mai mic nu le afecteaza.
# NU se aplica la PCAP-uri incarcate (_on_load_clicked) - acelea au nevoie
# de lista COMPLETA, fixa, nu de o fereastra glisanta
MAX_ALL_PACKETS = 50_000


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
        forensics_panel: ForensicsPanel | None = None,
    ) -> None:
        super().__init__()
        self._block_manager = block_manager
        self._event_store = event_store
        self._signatures_panel = signatures_panel
        self._traffic_panel = traffic_panel
        self._traffic_panel.analyze_requested.connect(self._on_traffic_analyze_requested)
        self._traffic_panel.reconstruct_requested.connect(self._on_traffic_reconstruct_requested)
        self._logs_panel = logs_panel
        self._forensics_panel = forensics_panel
        self._logs_panel.analyze_requested.connect(self._on_log_analyze_requested)
        self._ml_settings = ml_settings if ml_settings is not None else MlSettings()
        self._response_settings = (
            response_settings if response_settings is not None else ResponseSettings()
        )

        self._status_label = QLabel("niciun fisier incarcat")
        # BUG REAL gasit de user: fara word wrap, un mesaj de status lung
        # (ex: "nu s-a putut identifica conexiunea...") forteaza latimea
        # minima a QLabel-ului, deci si fereastra principala se redimensioneaza
        # vizibil, fara sa apara vreun dialog - parea o eroare silentioasa
        self._status_label.setWordWrap(True)
        # doar word wrap nu ajunge - QLabel.sizeHint() ramane bazat pe
        # latimea textului nefragmentat, deci fara o latime maxima explicita
        # layout-ul tot ar creste fereastra ca sa incapa mesajul pe un rand
        self._status_label.setMaximumWidth(400)

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
        self._brute_force_tracker: BruteForceTracker | None = None
        self._arp_spoof_tracker: ArpSpoofTracker | None = None
        self._dns_tunnel_tracker: DnsTunnelTracker | None = None
        self._payload_tracker: PayloadSignatureTracker | None = None
        self._live_hybrid: LiveHybridAnalyzer | None = None
        self._modern_live_hybrid: ModernLiveHybridAnalyzer | None = None
        self._packet_count = 0
        self._event_items: dict[tuple[str, str], QListWidgetItem] = {}
        # list[] initial (gol, oricum) - devine deque(maxlen=MAX_ALL_PACKETS)
        # la Start monitorizare (live, plafonat) sau list complet la
        # incarcare PCAP (_on_load_clicked, neplafonat - vezi MAX_ALL_PACKETS)
        self._all_packets: list[PacketMeta] = []
        self._inspector_dialogs: list[ConnectionInspectorDialog] = []
        self._timeline_dialogs: list[ConnectionTimelineDialog] = []
        self._expert_model = self._try_load_expert_model()
        # model expert MODERN (CSE-CIC-IDS2018) - complet independent de cel
        # de mai sus, "a doua opinie" doar la inspectie manuala (vezi
        # _analyze_connection). None e un caz normal - inca nu toata lumea
        # a rulat scripts/prepare_cse_cic_ids2018.py + train_modern_expert_model.py
        self._modern_expert_model = self._try_load_modern_expert_model()

        self._ml_timer = QTimer(self)
        self._ml_timer.timeout.connect(self._on_ml_evaluation_tick)

    @staticmethod
    def _try_load_expert_model() -> ExpertModel | None:
        try:
            return ExpertModel.load()
        except FileNotFoundError:
            return None

    @staticmethod
    def _try_load_modern_expert_model() -> ModernExpertModel | None:
        try:
            return ModernExpertModel.load()
        except FileNotFoundError:
            return None

    def modern_expert_model_loaded(self) -> bool:
        return self._modern_expert_model is not None

    def modern_expert_metrics(self) -> dict[str, float] | None:
        """performanta pe test set a modelului MODERN, calculata la
        (re)antrenare si salvata alaturi de model - vezi
        nids.ml.modern.model.build_metrics(). None daca modelul nu e
        incarcat sau a fost salvat inainte de introducerea acestui camp"""
        if self._modern_expert_model is None:
            return None
        return self._modern_expert_model.metrics

    # --- status pentru panoul ML ---

    def expert_model_loaded(self) -> bool:
        return self._expert_model is not None

    def local_model_status(self) -> LocalModelStatus | None:
        """status al modelului local PRINCIPAL (modern, CSE-CIC-IDS2018) -
        vezi DATASET-COMPARISON.md, Faza 6: modelul modern e folosit acum
        constant ca principal, cel vechi (NSL-KDD) ramane doar "a doua
        opinie" (old_local_model_status())"""
        if self._modern_live_hybrid is None:
            return None
        manager = self._modern_live_hybrid.local_manager
        return LocalModelStatus(
            is_learning=manager.is_learning,
            samples_collected=manager.samples_collected,
            min_training_samples=manager.min_training_samples,
        )

    def old_local_model_status(self) -> LocalModelStatus | None:
        """status al modelului local VECHI (NSL-KDD) - ramas doar ca "a
        doua opinie", ruleaza in fundal (antrenat continuu, la fel ca
        inainte) dar nu mai genereaza evenimente principale"""
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
        if self._forensics_panel is not None:
            self._forensics_panel.load_samples(read_pcap_payload_samples(path))

        threshold = self._signatures_panel.threshold()
        window = self._signatures_panel.window_seconds()
        sensitive_ports = self._signatures_panel.sensitive_ports()
        brute_force_threshold = self._signatures_panel.brute_force_threshold()
        brute_force_window = self._signatures_panel.brute_force_window_seconds()
        brute_force_ports = self._signatures_panel.brute_force_ports()
        dns_min_label_length = self._signatures_panel.dns_min_label_length()
        dns_min_entropy = self._signatures_panel.dns_min_entropy()
        payload_signatures_enabled = self._signatures_panel.payload_signatures_enabled()
        # Faza 6 (vezi DATASET-COMPARISON.md): modelul MODERN e principal -
        # analyze_pcap_modern_hybrid() incearca primul. daca userul nu l-a
        # antrenat inca (scripts/prepare_cse_cic_ids2018.py + train_modern_expert_model.py),
        # cade pe modelul vechi (NSL-KDD) - mai bine decat sa sara direct
        # la "doar semnaturi" cand exista totusi UN model ML disponibil
        if self._modern_expert_model is not None:
            events = analyze_pcap_modern_hybrid(
                path,
                self._modern_expert_model,
                port_scan_threshold=threshold,
                port_scan_window=window,
                sensitive_ports=sensitive_ports,
                brute_force_threshold=brute_force_threshold,
                brute_force_window=brute_force_window,
                brute_force_ports=brute_force_ports,
                dns_min_label_length=dns_min_label_length,
                dns_min_entropy=dns_min_entropy,
                payload_signatures_enabled=payload_signatures_enabled,
            )
        elif self._expert_model is not None:
            events = analyze_pcap_hybrid(
                path,
                self._expert_model,
                port_scan_threshold=threshold,
                port_scan_window=window,
                sensitive_ports=sensitive_ports,
                brute_force_threshold=brute_force_threshold,
                brute_force_window=brute_force_window,
                brute_force_ports=brute_force_ports,
                dns_min_label_length=dns_min_label_length,
                dns_min_entropy=dns_min_entropy,
                payload_signatures_enabled=payload_signatures_enabled,
            )
        else:
            events = analyze_pcap(
                path,
                port_scan_threshold=threshold,
                port_scan_window=window,
                sensitive_ports=sensitive_ports,
                brute_force_threshold=brute_force_threshold,
                brute_force_window=brute_force_window,
                brute_force_ports=brute_force_ports,
                dns_min_label_length=dns_min_label_length,
                dns_min_entropy=dns_min_entropy,
                payload_signatures_enabled=payload_signatures_enabled,
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
        if self._forensics_panel is not None:
            self._forensics_panel.clear()
        self._all_packets = deque(maxlen=MAX_ALL_PACKETS)
        self._stream_analyzer = StreamAnalyzer(
            port_scan_threshold=self._signatures_panel.threshold(),
            window_seconds=self._signatures_panel.window_seconds(),
        )
        self._sensitive_tracker = SensitivePortTracker(self._signatures_panel.sensitive_ports())
        self._brute_force_tracker = BruteForceTracker(
            threshold=self._signatures_panel.brute_force_threshold(),
            window_seconds=self._signatures_panel.brute_force_window_seconds(),
            target_ports=self._signatures_panel.brute_force_ports(),
        )
        self._arp_spoof_tracker = ArpSpoofTracker()
        self._dns_tunnel_tracker = DnsTunnelTracker(
            min_label_length=self._signatures_panel.dns_min_label_length(),
            min_entropy=self._signatures_panel.dns_min_entropy(),
        )
        self._payload_tracker = (
            PayloadSignatureTracker() if self._signatures_panel.payload_signatures_enabled() else None
        )
        # modelul vechi (NSL-KDD) ramane pornit in fundal - continua sa se
        # antreneze pe traficul live (altfel modelul lui local ar ramane
        # inghetat/"inca invata" mereu), dar evenimentele lui NU mai devin
        # principale (vezi _on_ml_evaluation_tick) - doar "a doua opinie",
        # disponibila la cerere din Loguri/Trafic (Faza 6, DATASET-COMPARISON.md)
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

        # modelul MODERN (CSE-CIC-IDS2018) - principal, genereaza
        # evenimentele afisate/salvate/eligibile pentru blocare automata
        modern_local_manager = ModernLocalModelManager.load_or_new(
            min_training_samples=self._ml_settings.min_training_samples,
            retrain_every=self._ml_settings.retrain_every,
            max_buffer_size=self._ml_settings.max_buffer_size,
            contamination=self._ml_settings.contamination,
            n_estimators=self._ml_settings.n_estimators,
        )
        self._modern_live_hybrid = ModernLiveHybridAnalyzer(
            self._modern_expert_model,
            modern_local_manager,
            strict_reporting=self._ml_settings.strict_reporting,
        )
        self._packet_count = 0

        self._thread = LiveCaptureThread()
        self._thread.packet_captured.connect(self._on_live_packet)
        self._thread.arp_frame_captured.connect(self._on_live_arp_frame)
        self._thread.dns_query_captured.connect(self._on_live_dns_query)
        self._thread.payload_sample_captured.connect(self._on_live_payload_sample)
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
        if (
            self._modern_live_hybrid is not None
            and not self._modern_live_hybrid.local_manager.is_learning
        ):
            self._modern_live_hybrid.local_manager.save()

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
        self._traffic_chart.record_packet(pkt)
        self._all_packets.append(pkt)

        if self._live_hybrid is not None:
            self._live_hybrid.add_packet(pkt)
        if self._modern_live_hybrid is not None:
            self._modern_live_hybrid.add_packet(pkt)

        if self._stream_analyzer is not None:
            update = self._stream_analyzer.process_packet(pkt)
            if update is not None:
                self._apply_scan_update(update)

        if self._sensitive_tracker is not None:
            sensitive_event = self._sensitive_tracker.process_packet(pkt)
            if sensitive_event is not None:
                self._append_events([sensitive_event])
                self._traffic_chart.record_event(sensitive_event.severity)

        if self._brute_force_tracker is not None:
            brute_force_event = self._brute_force_tracker.process_packet(pkt)
            if brute_force_event is not None:
                self._append_events([brute_force_event])
                self._traffic_chart.record_event(brute_force_event.severity)

    def _on_live_arp_frame(self, frame: ArpFrame) -> None:
        if self._arp_spoof_tracker is None:
            return
        event = self._arp_spoof_tracker.process_frame(frame)
        if event is not None:
            self._append_events([event])
            self._traffic_chart.record_event(event.severity)

    def _on_live_dns_query(self, query: DnsQuery) -> None:
        if self._dns_tunnel_tracker is None:
            return
        event = self._dns_tunnel_tracker.process_query(query)
        if event is not None:
            self._append_events([event])
            self._traffic_chart.record_event(event.severity)

    def _on_live_payload_sample(self, sample: PayloadSample) -> None:
        if self._forensics_panel is not None:
            self._forensics_panel.add_sample(sample)
        if self._payload_tracker is None:
            return
        event = self._payload_tracker.process_sample(sample)
        if event is not None:
            self._append_events([event])
            self._traffic_chart.record_event(event.severity)

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
        # modelul vechi (NSL-KDD) tot ruleaza evaluate() - altfel modelul
        # lui local nu s-ar mai antrena niciodata din trafic live (process()
        # e apelat DIN evaluate(), nu din add_packet()) si ar ramane "inca
        # invata" la infinit, inutil ca "a doua opinie". rezultatul lui insa
        # NU mai devine eveniment principal (nu se afiseaza, nu se salveaza,
        # nu conteaza pentru blocarea automata) - vezi DATASET-COMPARISON.md,
        # Faza 6
        if self._live_hybrid is not None:
            self._live_hybrid.evaluate()

        if self._modern_live_hybrid is None:
            return
        events = self._modern_live_hybrid.evaluate()
        for event in events:
            self._traffic_chart.record_event(event.severity)
            self._maybe_auto_block(event)
        self._append_events(events)

        old_counts, modern_counts = self._model_comparison_counts()
        self._traffic_chart.update_model_comparison(old_counts, modern_counts)

    def _model_comparison_counts(self) -> tuple[dict[str, int], dict[str, int]]:
        """totaluri cumulative pe sesiune, per tip de acord - pentru
        graficul "Comparatie modele" (TrafficChartPanel). foloseste
        agreement_counts direct de pe analizoare (INDIFERENT daca strict
        de raportare a suprimat evenimentul vizibil) - vrem sa vedem cum
        se comporta de fapt cele doua modele, nu doar ce a ajuns in Loguri"""

        def _labeled(analyzer) -> dict[str, int]:
            if analyzer is None:
                return {}
            return {
                _AGREEMENT_SHORT_LABELS[agreement]: count
                for agreement, count in analyzer.agreement_counts.items()
            }

        return _labeled(self._live_hybrid), _labeled(self._modern_live_hybrid)

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
        if (
            self._modern_live_hybrid is not None
            and not self._modern_live_hybrid.local_manager.is_learning
        ):
            self._modern_live_hybrid.local_manager.save()
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

    def _on_traffic_reconstruct_requested(self, pkt: PacketMeta) -> None:
        """"packet forensics": spre deosebire de analiza ML (features
        agregate), aici arati userului fluxul BRUT, pachet cu pachet, al
        conexiunii complete - nu are nevoie de niciun model, doar de
        _all_packets, deja pastrat pentru sesiunea curenta"""
        matches = packets_for_connection(list(self._all_packets), pkt)
        if not matches:
            self._status_label.setText("nu s-au gasit alte pachete pentru aceasta conexiune")
            return
        dialog = ConnectionTimelineDialog(matches, pkt, parent=self)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._timeline_dialogs.append(dialog)
        dialog.finished.connect(lambda: self._timeline_dialogs.remove(dialog))
        dialog.show()

    def _on_log_analyze_requested(self, entry: StoredEvent) -> None:
        """analog cu analiza din Trafic, dar pornind de la un rand din
        Loguri. daca evenimentul are o "poza" salvata a analizei
        (assessment_json - vezi LiveHybridAnalyzer/ModernLiveHybridAnalyzer),
        o folosim direct, indiferent de sesiune - nu are nevoie de
        pachetele brute, care oricum nu mai exista dupa un restart. altfel
        (evenimente foarte vechi, salvate inainte de aceasta functionalitate)
        incercam sa recalculam din traficul sesiunii curente, daca mai e
        disponibil"""
        if entry.assessment_json is not None:
            old_assessment, modern_assessment = _load_assessment_json(entry.assessment_json)
            self._show_inspector(old_assessment, modern_assessment)
            return

        # BUG REAL gasit de user: brute-force/porturi sensibile salveaza
        # dest_ip/dest_port (pentru context), dar NU src_port - nu exista
        # un singur port sursa asociat (brute-force = mai multe incercari,
        # deci mai multe porturi sursa). fara src_port, _find_matching_connection()
        # nu poate gasi NICIODATA o potrivire exacta - trebuia verificat
        # explicit aici, altfel cade in mesajul generic "nu s-a putut
        # identifica conexiunea", care pare identic cu "nu se intampla nimic"
        if entry.dest_ip is None or entry.src_port is None:
            QMessageBox.information(
                self,
                "Analiza indisponibila",
                "Acest eveniment nu are o conexiune ML asociata - e generat de o "
                "semnatura (port scan, brute-force, porturi sensibile, ARP spoofing, "
                "DNS tunneling, honeypot) sau de o actiune manuala, nu de o evaluare "
                "a modelelor ML.",
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

        records = extract_nsl_kdd_style_features(list(self._all_packets))
        record = _find_matching_connection(records, src_ip, src_port, dst_ip, dst_port, protocol)
        if record is None:
            self._status_label.setText(
                "nu s-a putut identifica conexiunea - probabil traficul brut nu mai e "
                "disponibil (alta sesiune sau pachete deja iesite din istoric)"
            )
            return

        local_manager = self._live_hybrid.local_manager if self._live_hybrid is not None else None
        assessment = assess_connection(record, self._expert_model, local_manager)
        modern_assessment = self._assess_modern_connection(src_ip, src_port, dst_ip, dst_port, protocol)
        self._show_inspector(assessment, modern_assessment)

    def _assess_modern_connection(
        self,
        src_ip: str,
        src_port: int | None,
        dst_ip: str,
        dst_port: int | None,
        protocol: str | None,
    ):
        """"a doua opinie" (CSE-CIC-IDS2018) - complet optionala si
        best-effort: None daca modelul modern nu a fost antrenat inca
        (scripts/prepare_cse_cic_ids2018.py + train_modern_expert_model.py,
        vezi DATASET-COMPARISON.md) sau daca nu se gaseste un flux
        corespunzator. NU intrerupe niciodata analiza principala (NSL-KDD)"""
        if self._modern_expert_model is None:
            return None
        flows = extract_cicflow_features(list(self._all_packets))
        flow = _find_matching_flow(flows, src_ip, src_port, dst_ip, dst_port, protocol)
        if flow is None:
            return None
        # local_manager=None: inca nu exista o sesiune persistenta de
        # monitorizare pe modelele moderne (Faza 6, urmeaza) - la fel ca la
        # modelul vechi, care arata "model local indisponibil" pentru
        # analiza pe un PCAP incarcat, fara monitorizare live in paralel
        return assess_modern(flow, self._modern_expert_model, local_manager=None)

    def _show_inspector(
        self,
        assessment: ConnectionAssessment | None,
        modern_assessment: ModernAssessment | None = None,
    ) -> None:
        dialog = ConnectionInspectorDialog(assessment, parent=self, modern_assessment=modern_assessment)
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


def _load_assessment_json(
    raw: str,
) -> tuple[ConnectionAssessment | None, ModernAssessment | None]:
    """o "poza" salvata poate fi din modelul vechi (asa functiona initial,
    inainte de Faza 6 - vezi DATASET-COMPARISON.md) sau din cel modern
    (implicit acum, singurul care mai salveaza assessment_json pentru
    evenimente live - ModernLiveHybridAnalyzer.evaluate()). cheia "model"
    lipseste din blob-urile deja salvate pe disc, de dinainte de aceasta
    distinctie - absenta ei inseamna implicit "old", ca sa nu se rupa
    compatibilitatea cu ce e deja in baza de date a userului"""
    payload = json.loads(raw)
    if payload.get("model") == "modern":
        return None, modern_assessment_from_json(raw)
    return assessment_from_json(raw), None


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


def _find_matching_flow(
    flows: list[CicFlowFeatures],
    src_ip: str,
    src_port: int | None,
    dst_ip: str,
    dst_port: int | None,
    protocol: str | None,
) -> CicFlowFeatures | None:
    """echivalentul lui _find_matching_connection, pentru schema modelului
    expert modern (CicFlowFeatures.protocol, nu .protocol_type)"""
    for flow in flows:
        forward = (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port)
        backward = (flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port)
        pair = (src_ip, src_port, dst_ip, dst_port)
        if pair not in (forward, backward):
            continue
        if protocol is not None and flow.protocol != protocol:
            continue
        return flow
    return None


def _format_event(event: Event) -> str:
    return f"[{event.severity.value}] {event.event_type} - {event.source_ip} - {event.description}"


def _make_event_item(event: Event) -> QListWidgetItem:
    item = QListWidgetItem(_format_event(event))
    item.setForeground(_SEVERITY_COLOR[event.severity])
    item.setData(Qt.ItemDataRole.UserRole, event)
    return item
