from __future__ import annotations

import time
from collections import deque
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from nids.capture.packet_meta import PacketMeta
from nids.capture.payload_meta import PayloadSample

_PAYLOAD_COLUMNS = ["timp", "sursa", "destinatie", "port dest", "dimensiune"]
# payload-ul brut nu e persistat pe disc (aceeasi decizie ca la semnaturile
# malware in payload, vezi NOTES.md) - doar pastrat scurt in memorie
# (fereastra glisanta) pentru inspectie manuala pe durata sesiunii curente
_MAX_SAMPLES = 200

_TIMELINE_COLUMNS = ["timp", "directie", "sursa", "destinatie", "protocol", "flag-uri TCP", "dimensiune"]


def hex_dump(data: bytes, width: int = 16) -> str:
    """format clasic de hex dump: offset | octeti in hexa | reprezentare
    ASCII (caracterele neafisabile devin '.') - suficient pentru inspectie
    manuala, nu incearca sa decodeze niciun protocol de aplicatie"""
    if not data:
        return "(fara date)"
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<{width * 3}} {ascii_part}")
    return "\n".join(lines)


def packets_for_connection(all_packets: list[PacketMeta], reference: PacketMeta) -> list[PacketMeta]:
    """toate pachetele aceleiasi conexiuni (ambele directii), in ordine
    cronologica - identitatea e perechea de capete + protocol, la fel ca
    nids/ml/features/connection.py::_connection_key(), dar aici pastram
    fiecare pachet individual (nu agregam intr-un singur record) - o
    vedere "pachet cu pachet" a schimbului complet, complementara analizei
    ML (care arata features agregate, nu fluxul brut)"""
    pair = frozenset({(reference.src_ip, reference.src_port), (reference.dst_ip, reference.dst_port)})
    matches = [
        p
        for p in all_packets
        if p.protocol == reference.protocol
        and frozenset({(p.src_ip, p.src_port), (p.dst_ip, p.dst_port)}) == pair
    ]
    return sorted(matches, key=lambda p: p.timestamp)


class HexDumpDialog(QDialog):
    """non-modal (ca ConnectionInspectorDialog) - mai multe pot fi
    deschise simultan, nu blocheaza restul aplicatiei"""

    def __init__(self, sample: PayloadSample, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(
            f"Payload: {sample.src_ip} -> {sample.dst_ip}:{sample.dst_port} "
            f"({len(sample.payload)} octeti)"
        )

        text = QTextEdit()
        text.setReadOnly(True)
        text.setFontFamily("Consolas")
        text.setPlainText(hex_dump(sample.payload))

        layout = QVBoxLayout(self)
        layout.addWidget(text)
        self.resize(720, 480)


class ConnectionTimelineDialog(QDialog):
    """non-modal, la fel ca HexDumpDialog/ConnectionInspectorDialog -
    lista cronologica a TUTUROR pachetelor unei conexiuni, ambele
    directii, cu timp relativ fata de primul pachet"""

    def __init__(self, packets: list[PacketMeta], reference: PacketMeta, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(
            f"Conexiune: {reference.src_ip}:{reference.src_port} <-> "
            f"{reference.dst_ip}:{reference.dst_port} ({reference.protocol})"
        )

        table = QTableWidget(len(packets), len(_TIMELINE_COLUMNS))
        table.setHorizontalHeaderLabels(_TIMELINE_COLUMNS)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(
            len(_TIMELINE_COLUMNS) - 1, QHeaderView.ResizeMode.Stretch
        )

        start = packets[0].timestamp if packets else 0.0
        origin = (reference.src_ip, reference.src_port)
        for row, p in enumerate(packets):
            direction = "->" if (p.src_ip, p.src_port) == origin else "<-"
            values = [
                f"+{p.timestamp - start:.3f}s",
                direction,
                f"{p.src_ip}:{p.src_port}" if p.src_port is not None else p.src_ip,
                f"{p.dst_ip}:{p.dst_port}" if p.dst_port is not None else p.dst_ip,
                p.protocol,
                p.tcp_flags or "-",
                str(p.length),
            ]
            for col, value in enumerate(values):
                table.setItem(row, col, QTableWidgetItem(value))

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"{len(packets)} pachete in aceasta conexiune"))
        layout.addWidget(table)
        self.resize(760, 500)


class ForensicsPanel(QWidget):
    """payload-urile brute capturate (semnaturi malware in payload
    partajeaza aceeasi sursa) - fereastra glisanta in memorie, NU
    persistata pe disc (aceeasi decizie ca payload_meta.py). dublu-click
    pe un rand deschide hex dump-ul complet. self-continut, la fel ca
    HoneypotPanel - nu are nevoie sa fie citit de alt panou"""

    def __init__(self) -> None:
        super().__init__()
        self._samples: deque[tuple[float, PayloadSample]] = deque(maxlen=_MAX_SAMPLES)
        self._hex_dialogs: list[HexDumpDialog] = []

        self._table = QTableWidget(0, len(_PAYLOAD_COLUMNS))
        self._table.setHorizontalHeaderLabels(_PAYLOAD_COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(
            len(_PAYLOAD_COLUMNS) - 1, QHeaderView.ResizeMode.Stretch
        )
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.doubleClicked.connect(self._on_row_double_clicked)

        hint = QLabel(
            "dublu-click pe un rand pentru hex dump complet - doar ultimele "
            f"{_MAX_SAMPLES} payload-uri sunt pastrate (in memorie, nu pe disc)"
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #8a8a8a;")

        layout = QVBoxLayout(self)
        layout.addWidget(self._table)
        layout.addWidget(hint)

    def add_sample(self, sample: PayloadSample, timestamp: float | None = None) -> None:
        ts = timestamp if timestamp is not None else time.time()
        self._samples.appendleft((ts, sample))

        self._table.insertRow(0)
        self._fill_row(0, ts, sample)
        if self._table.rowCount() > _MAX_SAMPLES:
            self._table.removeRow(self._table.rowCount() - 1)

    def load_samples(self, samples: list[PayloadSample]) -> None:
        """pentru un PCAP incarcat dintr-o data - inlocuieste tot"""
        self._samples.clear()
        self._table.setRowCount(0)
        for sample in samples[-_MAX_SAMPLES:]:
            self.add_sample(sample)

    def clear(self) -> None:
        self._samples.clear()
        self._table.setRowCount(0)

    def _fill_row(self, row: int, ts: float, sample: PayloadSample) -> None:
        values = [
            datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
            sample.src_ip,
            sample.dst_ip,
            str(sample.dst_port) if sample.dst_port is not None else "-",
            str(len(sample.payload)),
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            if column == 0:
                item.setData(Qt.ItemDataRole.UserRole, sample)
            self._table.setItem(row, column, item)

    def _sample_at(self, row: int) -> PayloadSample | None:
        if row < 0:
            return None
        item = self._table.item(row, 0)
        if item is None:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def _on_row_double_clicked(self, index) -> None:
        sample = self._sample_at(index.row())
        if sample is None:
            return
        self._open_hex_dump(sample)

    def _open_hex_dump(self, sample: PayloadSample) -> None:
        dialog = HexDumpDialog(sample, self)
        self._hex_dialogs.append(dialog)
        dialog.finished.connect(lambda: self._hex_dialogs.remove(dialog))
        dialog.show()
