from __future__ import annotations

import threading

from PySide6.QtCore import QThread, Signal

from nids.capture.live_capture import capture_live


class LiveCaptureThread(QThread):
    """subclaseaza QThread direct (nu worker + moveToThread) pentru ca
    run() e un singur apel blocant de lunga durata, nu o serie de sarcini
    scurte - nu are nevoie de event loop propriu (exec()), doar sa ruleze
    si sa se opreasca curat. QThread.finished se emite automat cand run()
    se termina, fara cod suplimentar"""

    packet_captured = Signal(object)
    arp_frame_captured = Signal(object)
    dns_query_captured = Signal(object)
    payload_sample_captured = Signal(object)
    error = Signal(str)

    def __init__(self, interface: str | None = None, parent=None) -> None:
        super().__init__(parent)
        self._interface = interface
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        try:
            capture_live(
                self.packet_captured.emit,
                on_arp=self.arp_frame_captured.emit,
                on_dns=self.dns_query_captured.emit,
                on_payload=self.payload_sample_captured.emit,
                interface=self._interface,
                stop_event=self._stop_event,
            )
        except Exception as exc:  # thread separat, nu poate lasa exceptia sa crape aplicatia
            self.error.emit(str(exc))
