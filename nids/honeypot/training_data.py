from __future__ import annotations

import time
from pathlib import Path

import joblib

from nids.capture.packet_meta import PacketMeta
from nids.honeypot.listener import HoneypotHit

DEFAULT_TRAINING_DATA_PATH = (
    Path(__file__).resolve().parent.parent.parent / "data" / "models" / "honeypot_training_sessions.joblib"
)

# nu conteaza ca IP real - doar o cheie stabila, comuna tuturor
# interactiunilor honeypot, ca sa reprezinte corect faptul ca toate
# "ataca" ACELASI host (honeypot-ul ruleaza pe o singura masina) - asta
# conteaza pentru statisticile per-destinatie din TrafficWindowTracker
HONEYPOT_HOST_IP = "honeypot-host"


def hit_to_packets(hit: HoneypotHit, timestamp: float | None = None) -> list[PacketMeta]:
    """converteste o interactiune honeypot intr-o secventa mica de pachete
    sintetice (SYN, SYN-ACK, eventual date primite, FIN) - NU pachete
    reale, doar suficient de plauzibile ca extract_nsl_kdd_style_features()
    (acelasi extractor folosit pentru trafic real) sa produca un record cu
    cele 28 de features, fara sa scriem un extractor separat doar pentru
    honeypot. o interactiune cu honeypot-ul e prin definitie un atac -
    reflectat aici doar in FORMA pachetelor (flag SF, conexiune completa),
    eticheta explicita de "atac" se aplica separat, la reantrenare"""
    ts = timestamp if timestamp is not None else time.time()
    end = ts + max(hit.duration, 0.0)

    packets = [
        PacketMeta(
            timestamp=ts,
            src_ip=hit.src_ip,
            dst_ip=HONEYPOT_HOST_IP,
            protocol="tcp",
            length=40,
            src_port=hit.src_port,
            dst_port=hit.dst_port,
            tcp_flags="S",
        ),
        PacketMeta(
            timestamp=ts,
            src_ip=HONEYPOT_HOST_IP,
            dst_ip=hit.src_ip,
            protocol="tcp",
            length=40,
            src_port=hit.dst_port,
            dst_port=hit.src_port,
            tcp_flags="SA",
        ),
    ]
    if hit.bytes_received > 0:
        packets.append(
            PacketMeta(
                timestamp=ts,
                src_ip=hit.src_ip,
                dst_ip=HONEYPOT_HOST_IP,
                protocol="tcp",
                length=hit.bytes_received,
                src_port=hit.src_port,
                dst_port=hit.dst_port,
                tcp_flags="A",
            )
        )
    packets.append(
        PacketMeta(
            timestamp=end,
            src_ip=HONEYPOT_HOST_IP,
            dst_ip=hit.src_ip,
            protocol="tcp",
            length=0,
            src_port=hit.dst_port,
            dst_port=hit.src_port,
            tcp_flags="FA",
        )
    )
    return packets


class HoneypotTrainingStore:
    """acumuleaza sesiunile (cate o lista de pachete per interactiune)
    persistent pe disc, intre pornirile aplicatiei - la fel ca
    LocalModelManager, care nu reseteaza bufferul la fiecare sesiune
    (userul a cerut explicit asta si pentru modelul local, vezi NOTES.md).
    fara asta, ar trebui sa lasi honeypot-ul sa colecteze ore intregi
    intr-o singura rulare ca sa aiba destule esantioane pentru reantrenare"""

    def __init__(self, path: Path = DEFAULT_TRAINING_DATA_PATH) -> None:
        self._path = path
        self._sessions: list[list[PacketMeta]] = self._load()

    def _load(self) -> list[list[PacketMeta]]:
        if self._path.exists():
            return joblib.load(self._path)
        return []

    def add_hit(self, hit: HoneypotHit) -> None:
        self._sessions.append(hit_to_packets(hit))
        self._save()

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._sessions, self._path)

    def packets(self) -> list[PacketMeta]:
        """toate pachetele sintetice, din toate sesiunile - ce trebuie
        pasat catre extract_nsl_kdd_style_features()"""
        return [pkt for session in self._sessions for pkt in session]

    def sample_count(self) -> int:
        """numarul de INTERACTIUNI (conexiuni) acumulate, nu de pachete
        sintetice - fiecare interactiune produce 3-4 pachete"""
        return len(self._sessions)

    def clear(self) -> None:
        self._sessions = []
        self._save()
