from __future__ import annotations

import threading

from PySide6.QtCore import QThread, Signal

from nids.honeypot.listener import run_honeypot


class HoneypotThread(QThread):
    """subclaseaza QThread direct, la fel ca LiveCaptureThread/
    SimulationThread - run() e un singur apel blocant (run_honeypot),
    nu o serie de sarcini scurte"""

    hit_detected = Signal(object)  # HoneypotHit
    bind_error = Signal(int, str)  # port, mesaj

    def __init__(self, ports: list[int], parent=None) -> None:
        super().__init__(parent)
        self._ports = ports
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        run_honeypot(
            self._ports,
            on_hit=self.hit_detected.emit,
            on_bind_error=self.bind_error.emit,
            stop_event=self._stop_event,
        )
