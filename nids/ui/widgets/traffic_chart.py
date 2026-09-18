from __future__ import annotations

from collections import Counter, deque

import pyqtgraph as pg
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QComboBox,
    QLabel,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from nids.capture.packet_meta import PacketMeta
from nids.core.event import Severity
from nids.ui.reverse_dns_thread import ReverseDnsThread
from nids.ui.widgets.ip_lookup_dialog import IpLookupResultsDialog

_WINDOW_SECONDS = 60
_TICK_MS = 1000
_TOP_TALKERS_COUNT = 8

_SEVERITY_COLOR = {
    Severity.LOW: "#4ec9b0",
    Severity.MEDIUM: "#dcdcaa",
    Severity.HIGH: "#f14c4c",
}

pg.setConfigOptions(background="#1e1e1e", foreground="#cccccc", antialias=True)


def _bar_plot(y_label: str) -> pg.PlotWidget:
    plot = pg.PlotWidget()
    plot.showGrid(y=True, alpha=0.2)
    plot.setLabel("left", y_label)
    return plot


class TrafficChartPanel(QWidget):
    """grafic live cu mai multe VEDERI comutabile (selector sus) - userul
    a descris graficul original (doar pachete/secunda) ca "util dar putin
    plictisitor" si a cerut mai multe date despre reteaua curenta, de
    vreme ce oricum se face un overhaul la partea de ML (vezi
    DATASET-COMPARISON.md). doar pentru monitorizarea live - PCAP-urile
    incarcate au timestamp-uri istorice, n-are sens pe un grafic "acum"

    vederile "pe secunda" (pachete, octeti) gliseaza pe ultimele
    _WINDOW_SECONDS - traficul mai vechi dispare din grafic (nu si din
    Loguri). vederile "protocol"/"top IP-uri" sunt CUMULATIVE pe toata
    sesiunea curenta (de la ultimul Start monitorizare/PCAP), resetate de
    clear() - nu are sens o fereastra glisanta de 60s pentru "cine e cel
    mai activ IP", ar sari prea mult"""

    def __init__(self) -> None:
        super().__init__()

        self._view_selector = QComboBox()
        self._view_selector.addItems(
            [
                "Pachete/secunda",
                "Octeti/secunda",
                "Protocol",
                "Top IP-uri sursa",
                "Comparatie modele",
            ]
        )
        self._view_selector.currentIndexChanged.connect(self._on_view_changed)

        self._plot = pg.PlotWidget()
        self._plot.showGrid(x=True, y=True, alpha=0.2)
        self._plot.setLabel("left", "pachete / secunda")
        self._plot.setLabel("bottom", "secunde in urma")
        self._plot.setXRange(-_WINDOW_SECONDS, 0, padding=0)
        self._plot.setYRange(0, 5, padding=0)
        self._curve = self._plot.plot(pen=pg.mkPen("#007acc", width=2))
        self._markers = pg.ScatterPlotItem(size=10)
        self._plot.addItem(self._markers)

        self._bytes_plot = pg.PlotWidget()
        self._bytes_plot.showGrid(x=True, y=True, alpha=0.2)
        self._bytes_plot.setLabel("left", "octeti / secunda")
        self._bytes_plot.setLabel("bottom", "secunde in urma")
        self._bytes_plot.setXRange(-_WINDOW_SECONDS, 0, padding=0)
        self._bytes_plot.setYRange(0, 5, padding=0)
        self._bytes_curve = self._bytes_plot.plot(pen=pg.mkPen("#4ec9b0", width=2))

        self._protocol_plot = _bar_plot("pachete")
        self._talkers_plot = _bar_plot("pachete")
        self._identify_button = QPushButton("Identifica IP-uri")
        self._identify_button.setToolTip(
            "DNS invers (PTR) + AS/organizatie/tara/prefix BGP (Team Cymru) "
            "pentru IP-urile afisate - informatie standard de retea, publica "
            "(ca nslookup/dig -x sau whois), nu date personale"
        )
        self._identify_button.clicked.connect(self._on_identify_clicked)
        talkers_page = QWidget()
        talkers_layout = QVBoxLayout(talkers_page)
        talkers_layout.setContentsMargins(0, 0, 0, 0)
        talkers_layout.addWidget(self._identify_button)
        talkers_layout.addWidget(self._talkers_plot)

        self._comparison_plot = _bar_plot("conexiuni evaluate")
        self._comparison_legend = QLabel(
            '<span style="color:#8a8a8a;">■</span> vechi (NSL-KDD)&nbsp;&nbsp;&nbsp;'
            '<span style="color:#007acc;">■</span> modern (CSE-CIC-IDS2018)'
        )
        comparison_page = QWidget()
        comparison_layout = QVBoxLayout(comparison_page)
        comparison_layout.setContentsMargins(0, 0, 0, 0)
        comparison_layout.addWidget(self._comparison_legend)
        comparison_layout.addWidget(self._comparison_plot)

        self._stack = QStackedWidget()
        self._stack.addWidget(self._plot)
        self._stack.addWidget(self._bytes_plot)
        self._stack.addWidget(self._protocol_plot)
        self._stack.addWidget(talkers_page)
        self._stack.addWidget(comparison_page)

        layout = QVBoxLayout(self)
        layout.addWidget(self._view_selector)
        layout.addWidget(self._stack)

        self._tick_x: deque[int] = deque(maxlen=_WINDOW_SECONDS)
        self._tick_y: deque[int] = deque(maxlen=_WINDOW_SECONDS)
        self._byte_tick_y: deque[int] = deque(maxlen=_WINDOW_SECONDS)
        self._current_second_count = 0
        self._current_second_bytes = 0
        self._tick_count = 0
        self._events: list[tuple[int, Severity]] = []

        # cumulative pe sesiune, nu fereastra glisanta - vezi docstring
        self._protocol_counts: Counter[str] = Counter()
        self._src_ip_counts: Counter[str] = Counter()

        # comparatie vechi vs modern - impinsa din DashboardPanel (nu
        # calculata aici, panoul nu stie nimic despre Agreement/ML) la
        # fiecare tick de evaluare ML, vezi update_model_comparison()
        self._old_agreement_counts: dict[str, int] = {}
        self._modern_agreement_counts: dict[str, int] = {}

        self._dns_thread: ReverseDnsThread | None = None
        self._lookup_dialogs: list[IpLookupResultsDialog] = []

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(_TICK_MS)

    def record_packet(self, pkt: PacketMeta) -> None:
        self._current_second_count += 1
        self._current_second_bytes += pkt.length
        self._protocol_counts[pkt.protocol] += 1
        self._src_ip_counts[pkt.src_ip] += 1

    def record_event(self, severity: Severity) -> None:
        self._events.append((self._tick_count, severity))

    def update_model_comparison(
        self, old_counts: dict[str, int], modern_counts: dict[str, int]
    ) -> None:
        """impins periodic din DashboardPanel (acelasi tick unde se
        evalueaza ambele modele) - inlocuieste tot, nu acumuleaza (cele
        doua dict-uri deja vin ca totaluri cumulative din
        LiveHybridAnalyzer.agreement_counts / ModernLiveHybridAnalyzer.agreement_counts)"""
        self._old_agreement_counts = old_counts
        self._modern_agreement_counts = modern_counts
        self._redraw()

    def clear(self) -> None:
        self._tick_x.clear()
        self._tick_y.clear()
        self._byte_tick_y.clear()
        self._current_second_count = 0
        self._current_second_bytes = 0
        self._tick_count = 0
        self._events = []
        self._protocol_counts.clear()
        self._src_ip_counts.clear()
        self._old_agreement_counts = {}
        self._modern_agreement_counts = {}
        self._redraw()

    def _on_view_changed(self, index: int) -> None:
        self._stack.setCurrentIndex(index)

    def _on_identify_clicked(self) -> None:
        ips = list(dict(self._src_ip_counts.most_common(_TOP_TALKERS_COUNT)))
        if not ips:
            return

        self._identify_button.setEnabled(False)
        self._identify_button.setText("se cauta...")

        self._dns_thread = ReverseDnsThread(ips)
        self._dns_thread.succeeded.connect(self._on_dns_resolved)
        self._dns_thread.failed.connect(self._on_dns_failed)
        self._dns_thread.finished.connect(self._on_dns_thread_finished)
        self._dns_thread.finished.connect(self._dns_thread.deleteLater)
        self._dns_thread.start()

    def _on_dns_resolved(self, results: dict[str, str | None]) -> None:
        dialog = IpLookupResultsDialog(results, parent=self)
        self._lookup_dialogs.append(dialog)
        dialog.finished.connect(lambda: self._lookup_dialogs.remove(dialog))
        dialog.show()

    def _on_dns_failed(self, message: str) -> None:
        # putin probabil (reverse_dns_lookup_many prinde erorile per-IP),
        # dar orice eroare tot trebuie sa ajunga vizibila, nu inghitita
        self._identify_button.setText(f"cautare esuata: {message}")

    def _on_dns_thread_finished(self) -> None:
        self._dns_thread = None
        self._identify_button.setEnabled(True)
        if self._identify_button.text() == "se cauta...":
            self._identify_button.setText("Identifica IP-uri")

    def _tick(self) -> None:
        self._tick_x.append(self._tick_count)
        self._tick_y.append(self._current_second_count)
        self._byte_tick_y.append(self._current_second_bytes)
        self._current_second_count = 0
        self._current_second_bytes = 0
        self._tick_count += 1

        cutoff = self._tick_count - _WINDOW_SECONDS
        self._events = [(t, s) for t, s in self._events if t >= cutoff]

        self._redraw()

    def _redraw(self) -> None:
        # actualizeaza TOATE vederile, nu doar cea vizibila acum - costul e
        # neglijabil (cateva bare/puncte, o data pe secunda) si evita ca o
        # vedere sa arate date invechite in clipa in care userul comuta pe
        # ea (ar trebui sa astepte pana la urmatorul tick)
        self._redraw_packets_per_second()
        self._redraw_bytes_per_second()
        self._redraw_bar(self._protocol_plot, self._protocol_counts, "#007acc")
        self._redraw_bar(
            self._talkers_plot,
            dict(self._src_ip_counts.most_common(_TOP_TALKERS_COUNT)),
            "#dcdcaa",
        )
        self._redraw_model_comparison()

    def _redraw_packets_per_second(self) -> None:
        # cel mai recent punct trebuie sa fie mereu la x=0 ("acum") -
        # folosim direct ultima valoare inregistrata, nu self._tick_count
        # (care e deja incrementat inainte de acest apel, ar da -1)
        now = self._tick_x[-1] if self._tick_x else self._tick_count
        x = [t - now for t in self._tick_x]
        y = list(self._tick_y)
        self._curve.setData(x, y)

        max_y = max(y) if y else 0
        self._plot.setYRange(0, max(max_y, 5) * 1.2, padding=0)

        if self._events:
            tick_to_y = dict(zip(self._tick_x, self._tick_y))
            spots = [
                {
                    "pos": (t - now, tick_to_y.get(t, 0)),
                    "brush": pg.mkBrush(_SEVERITY_COLOR[severity]),
                    "pen": pg.mkPen(None),
                    "size": 10,
                }
                for t, severity in self._events
            ]
            self._markers.setData(spots)
        else:
            self._markers.clear()

    def _redraw_bytes_per_second(self) -> None:
        now = self._tick_x[-1] if self._tick_x else self._tick_count
        x = [t - now for t in self._tick_x]
        y = list(self._byte_tick_y)
        self._bytes_curve.setData(x, y)

        max_y = max(y) if y else 0
        self._bytes_plot.setYRange(0, max(max_y, 5) * 1.2, padding=0)

    def _redraw_bar(self, plot: pg.PlotWidget, counts: dict[str, int], color: str) -> None:
        plot.clear()
        if not counts:
            return
        items = sorted(counts.items(), key=lambda kv: -kv[1])
        labels = [name for name, _ in items]
        values = [count for _, count in items]
        xs = list(range(len(labels)))
        plot.addItem(pg.BarGraphItem(x=xs, height=values, width=0.6, brush=color))
        plot.getAxis("bottom").setTicks([list(zip(xs, labels))])

    def _redraw_model_comparison(self) -> None:
        self._comparison_plot.clear()
        labels = sorted(set(self._old_agreement_counts) | set(self._modern_agreement_counts))
        if not labels:
            return

        xs = list(range(len(labels)))
        old_values = [self._old_agreement_counts.get(label, 0) for label in labels]
        modern_values = [self._modern_agreement_counts.get(label, 0) for label in labels]
        old_xs = [x - 0.2 for x in xs]
        modern_xs = [x + 0.2 for x in xs]

        self._comparison_plot.addItem(
            pg.BarGraphItem(x=old_xs, height=old_values, width=0.35, brush="#8a8a8a")
        )
        self._comparison_plot.addItem(
            pg.BarGraphItem(x=modern_xs, height=modern_values, width=0.35, brush="#007acc")
        )
        self._comparison_plot.getAxis("bottom").setTicks([list(zip(xs, labels))])
