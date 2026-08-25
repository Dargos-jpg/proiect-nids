from __future__ import annotations

from PySide6.QtCore import QThread, Signal

from nids.core.simulation import run_port_scan_simulation


class SimulationThread(QThread):
    """subclaseaza QThread direct, la fel ca LiveCaptureThread - run()
    e un singur apel blocant scurt (cateva conexiuni TCP cu timeout mic),
    nu are nevoie de exec()"""

    finished_ok = Signal(str)
    error = Signal(str)

    def run(self) -> None:
        try:
            target = run_port_scan_simulation()
            self.finished_ok.emit(target)
        except Exception as exc:  # thread separat, nu poate lasa exceptia sa crape aplicatia
            self.error.emit(str(exc))
