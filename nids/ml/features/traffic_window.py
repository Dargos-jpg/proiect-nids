from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from nids.ml.features.connection import ConnectionFeatures

TIME_WINDOW_SECONDS = 2.0
HOST_WINDOW_SIZE = 100

_ERROR_FLAGS = {"S0", "S1", "S2", "S3"}
_REJECT_FLAGS = {"REJ", "RSTO", "RSTR"}


@dataclass
class TrafficWindowFeatures:
    count: int
    srv_count: int
    serror_rate: float
    srv_serror_rate: float
    rerror_rate: float
    srv_rerror_rate: float
    same_srv_rate: float
    diff_srv_rate: float
    srv_diff_host_rate: float
    dst_host_count: int
    dst_host_srv_count: int
    dst_host_same_srv_rate: float
    dst_host_diff_srv_rate: float
    dst_host_same_src_port_rate: float
    dst_host_srv_diff_host_rate: float
    dst_host_serror_rate: float
    dst_host_srv_serror_rate: float
    dst_host_rerror_rate: float
    dst_host_srv_rerror_rate: float


@dataclass
class _WindowEntry:
    timestamp: float
    dst_ip: str
    service: str
    flag: str
    src_ip: str
    src_port: int | None


def _rate(count: int, total: int) -> float:
    return count / total if total > 0 else 0.0


class TrafficWindowTracker:
    """calculeaza cele 19 features 'traffic' din NSL-KDD, pe baza a doua
    ferestre alunecatoare:
    - fereastra de timp (ultimele TIME_WINDOW_SECONDS secunde, toate
      conexiunile recente) - pentru count/srv_count/*error_rate/*srv_rate
    - fereastra per-host (ultimele HOST_WINDOW_SIZE conexiuni catre
      aceeasi destinatie) - pentru toate campurile dst_host_*

    conexiunile trebuie procesate in ordine cronologica (dupa start_time).
    NU replica exact taxonomia originala NSL-KDD/MADAM-ID (are ambiguitati
    documentate chiar si in reimplementari academice) - e o aproximare
    interna consistenta, suficienta pentru modelul propriu, nu pentru
    compatibilitate stricta cu modelul expert antrenat pe NSL-KDD"""

    def __init__(
        self,
        time_window: float = TIME_WINDOW_SECONDS,
        host_window_size: int = HOST_WINDOW_SIZE,
    ) -> None:
        self._time_window = time_window
        self._host_window_size = host_window_size
        self._recent: deque[_WindowEntry] = deque()
        self._by_host: dict[str, deque[_WindowEntry]] = {}

    def process(self, conn: ConnectionFeatures) -> TrafficWindowFeatures:
        current = _WindowEntry(
            timestamp=conn.start_time,
            dst_ip=conn.dst_ip,
            service=conn.service,
            flag=conn.flag,
            src_ip=conn.src_ip,
            src_port=conn.src_port,
        )

        self._evict_older_than(conn.start_time - self._time_window)
        self._recent.append(current)
        time_window = list(self._recent)

        bucket = self._by_host.setdefault(conn.dst_ip, deque(maxlen=self._host_window_size))
        bucket.append(current)
        host_window = list(bucket)

        return self._compute(current, time_window, host_window)

    def _evict_older_than(self, cutoff: float) -> None:
        while self._recent and self._recent[0].timestamp < cutoff:
            self._recent.popleft()

    def _compute(
        self,
        current: _WindowEntry,
        time_window: list[_WindowEntry],
        host_window: list[_WindowEntry],
    ) -> TrafficWindowFeatures:
        count = len(time_window)
        same_srv = [c for c in time_window if c.service == current.service]
        srv_count = len(same_srv)

        serror_count = sum(1 for c in time_window if c.flag in _ERROR_FLAGS)
        rerror_count = sum(1 for c in time_window if c.flag in _REJECT_FLAGS)
        srv_serror_count = sum(1 for c in same_srv if c.flag in _ERROR_FLAGS)
        srv_rerror_count = sum(1 for c in same_srv if c.flag in _REJECT_FLAGS)
        srv_diff_host_count = sum(1 for c in same_srv if c.dst_ip != current.dst_ip)

        dst_host_count = len(host_window)
        dst_host_same_srv = [c for c in host_window if c.service == current.service]
        dst_host_srv_count = len(dst_host_same_srv)
        dst_host_same_port_count = sum(
            1 for c in host_window if c.src_port == current.src_port
        )
        dst_host_srv_diff_host_count = sum(
            1 for c in dst_host_same_srv if c.src_ip != current.src_ip
        )
        dst_host_serror_count = sum(1 for c in host_window if c.flag in _ERROR_FLAGS)
        dst_host_rerror_count = sum(1 for c in host_window if c.flag in _REJECT_FLAGS)
        dst_host_srv_serror_count = sum(1 for c in dst_host_same_srv if c.flag in _ERROR_FLAGS)
        dst_host_srv_rerror_count = sum(1 for c in dst_host_same_srv if c.flag in _REJECT_FLAGS)

        same_srv_rate = _rate(srv_count, count)
        dst_host_same_srv_rate = _rate(dst_host_srv_count, dst_host_count)

        return TrafficWindowFeatures(
            count=count,
            srv_count=srv_count,
            serror_rate=_rate(serror_count, count),
            srv_serror_rate=_rate(srv_serror_count, srv_count),
            rerror_rate=_rate(rerror_count, count),
            srv_rerror_rate=_rate(srv_rerror_count, srv_count),
            same_srv_rate=same_srv_rate,
            diff_srv_rate=1.0 - same_srv_rate,
            srv_diff_host_rate=_rate(srv_diff_host_count, srv_count),
            dst_host_count=dst_host_count,
            dst_host_srv_count=dst_host_srv_count,
            dst_host_same_srv_rate=dst_host_same_srv_rate,
            dst_host_diff_srv_rate=1.0 - dst_host_same_srv_rate,
            dst_host_same_src_port_rate=_rate(dst_host_same_port_count, dst_host_count),
            dst_host_srv_diff_host_rate=_rate(dst_host_srv_diff_host_count, dst_host_srv_count),
            dst_host_serror_rate=_rate(dst_host_serror_count, dst_host_count),
            dst_host_srv_serror_rate=_rate(dst_host_srv_serror_count, dst_host_srv_count),
            dst_host_rerror_rate=_rate(dst_host_rerror_count, dst_host_count),
            dst_host_srv_rerror_rate=_rate(dst_host_srv_rerror_count, dst_host_srv_count),
        )
