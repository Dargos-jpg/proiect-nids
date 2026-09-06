from __future__ import annotations

from PySide6.QtCore import QThread, Signal

from nids.scanner.vulnerability_scan import scan_targets


class ScanThread(QThread):
    """scanarea mai multor porturi/hosturi (fiecare cu propriul timeout de
    conectare) poate dura cateva secunde - pe un thread separat, la fel ca
    toate celelalte operatii de retea din proiect (LiveCaptureThread/
    SimulationThread/HoneypotThread), subclasare QThread directa"""

    succeeded = Signal(list)  # list[PortScanResult]
    failed = Signal(str)

    def __init__(self, hosts: list[str], ports: list[int], parent=None) -> None:
        super().__init__(parent)
        self._hosts = hosts
        self._ports = ports

    def run(self) -> None:
        try:
            results = scan_targets(self._hosts, self._ports)
        except Exception as exc:  # noqa: BLE001 - orice eroare trebuie sa ajunga in UI, nu sa crape thread-ul
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(results)
