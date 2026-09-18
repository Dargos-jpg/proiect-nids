from __future__ import annotations

from PySide6.QtCore import QThread, Signal

from nids.core.dns_lookup import lookup_ip_details_many


class ReverseDnsThread(QThread):
    """rezolvarea DNS inversa (PTR) + lookup-ul ASN/organizatie (Team
    Cymru, vezi nids/core/dns_lookup.py) pot dura (timeout per IP daca nu
    exista raspuns) - pe un thread separat, la fel ca toate celelalte
    operatii de retea din proiect (LiveCaptureThread/ScanThread/
    RetrainThread), ca UI-ul sa nu inghete cat asteapta raspunsuri"""

    succeeded = Signal(dict)  # {ip: IpLookupResult}
    failed = Signal(str)

    def __init__(self, ips: list[str], parent=None) -> None:
        super().__init__(parent)
        self._ips = ips

    def run(self) -> None:
        try:
            results = lookup_ip_details_many(self._ips)
        except Exception as exc:  # noqa: BLE001 - orice eroare trebuie sa ajunga in UI, nu sa crape thread-ul
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(results)
