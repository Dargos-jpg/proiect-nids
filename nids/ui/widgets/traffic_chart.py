from __future__ import annotations

from collections import deque

import pyqtgraph as pg
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QVBoxLayout, QWidget

from nids.core.event import Severity

_WINDOW_SECONDS = 60
_TICK_MS = 1000

_SEVERITY_COLOR = {
    Severity.LOW: "#4ec9b0",
    Severity.MEDIUM: "#dcdcaa",
    Severity.HIGH: "#f14c4c",
}

pg.setConfigOptions(background="#1e1e1e", foreground="#cccccc", antialias=True)


class TrafficChartPanel(QWidget):
    """grafic live cu volumul de trafic (pachete/secunda) + marcaje
    pentru evenimente noi (colorate dupa severitate) - ca sa vezi vizual
    daca un varf de trafic coincide cu o alerta. doar pentru
    monitorizarea live - PCAP-urile incarcate au timestamp-uri istorice,
    n-are sens sa apara pe un grafic care "acum" inseamna ceva real.

    fereastra gliseaza pe ultimele _WINDOW_SECONDS - traficul mai vechi
    dispare din grafic (nu si din lista de evenimente/Loguri, doar din
    reprezentarea vizuala)"""

    def __init__(self) -> None:
        super().__init__()

        self._plot = pg.PlotWidget()
        self._plot.showGrid(x=True, y=True, alpha=0.2)
        self._plot.setLabel("left", "pachete / secunda")
        self._plot.setLabel("bottom", "secunde in urma")
        self._plot.setXRange(-_WINDOW_SECONDS, 0, padding=0)
        self._plot.setYRange(0, 5, padding=0)

        self._curve = self._plot.plot(pen=pg.mkPen("#007acc", width=2))
        self._markers = pg.ScatterPlotItem(size=10)
        self._plot.addItem(self._markers)

        layout = QVBoxLayout(self)
        layout.addWidget(self._plot)

        self._tick_x: deque[int] = deque(maxlen=_WINDOW_SECONDS)
        self._tick_y: deque[int] = deque(maxlen=_WINDOW_SECONDS)
        self._current_second_count = 0
        self._tick_count = 0
        self._events: list[tuple[int, Severity]] = []

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(_TICK_MS)

    def record_packet(self) -> None:
        self._current_second_count += 1

    def record_event(self, severity: Severity) -> None:
        self._events.append((self._tick_count, severity))

    def clear(self) -> None:
        self._tick_x.clear()
        self._tick_y.clear()
        self._current_second_count = 0
        self._tick_count = 0
        self._events = []
        self._redraw()

    def _tick(self) -> None:
        self._tick_x.append(self._tick_count)
        self._tick_y.append(self._current_second_count)
        self._current_second_count = 0
        self._tick_count += 1

        cutoff = self._tick_count - _WINDOW_SECONDS
        self._events = [(t, s) for t, s in self._events if t >= cutoff]

        self._redraw()

    def _redraw(self) -> None:
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
