from __future__ import annotations

from PySide6.QtCore import QThread, Signal

from nids.capture.packet_meta import PacketMeta
from nids.ml.expert.retrain import retrain_with_honeypot_data


class RetrainThread(QThread):
    """antreneaza doua RandomForest-uri pe rand (baseline + varianta cu
    date honeypot) - poate dura cateva secunde, pe un thread separat ca
    UI-ul sa nu inghete, la fel ca LiveCaptureThread/SimulationThread/
    HoneypotThread (subclasare directa, un singur apel blocant in run())"""

    succeeded = Signal(object)  # RetrainResult
    failed = Signal(str)

    def __init__(self, honeypot_packets: list[PacketMeta], parent=None) -> None:
        super().__init__(parent)
        self._honeypot_packets = honeypot_packets

    def run(self) -> None:
        try:
            result = retrain_with_honeypot_data(self._honeypot_packets)
        except Exception as exc:  # noqa: BLE001 - orice eroare trebuie sa ajunga in UI, nu sa crape thread-ul
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(result)
