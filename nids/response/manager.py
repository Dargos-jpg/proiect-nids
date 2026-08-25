from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

DEFAULT_BLOCK_DURATION = timedelta(minutes=10)
DEFAULT_MAX_HISTORY = 200


class BlockRuleError(Exception):
    """add_rule (backend-ul de firewall injectat, ex: netsh) a esuat -
    cel mai frecvent motiv pe Windows: aplicatia nu ruleaza ca
    Administrator. BlockManager nu stie nimic despre netsh in sine, dar
    trebuie sa converteasca orice esec al backend-ului injectat intr-o
    exceptie proprie, catchabila explicit de UI - altfel un
    subprocess.CalledProcessError (detaliu de implementare al backend-ului
    concret) ar scapa necapturat pana la thread-ul UI si ar crapa
    aplicatia (bug real, gasit de user)"""


@dataclass
class BlockedIp:
    ip: str
    reason: str
    blocked_at: datetime
    expires_at: datetime


@dataclass
class BlockHistoryEntry:
    """o intrare de istoric traieste mai mult decat blocarea activa
    corespunzatoare - ramane in `history()` si dupa ce blocarea a
    expirat/a fost ridicata, ca userul sa vada ce s-a intamplat, nu doar
    ce e activ acum (tabelul de blocari active se goleste de la sine).
    unblocked_at/ended_by raman None cat timp blocarea e inca activa"""

    ip: str
    reason: str
    blocked_at: datetime
    expires_at: datetime
    unblocked_at: datetime | None = None
    ended_by: str | None = None  # "manual" | "expirat" | "oprire aplicatie" | None (activa)


class BlockManager:
    """gestioneaza blocarile temporare de IP - actiune safe/reversibila,
    niciodata permanenta (vezi CONTEXT-nids.md). backend-ul care chiar
    aplica regula de firewall e injectat (add_rule/remove_rule), ca sa
    poata fi inlocuit cu un fals in teste, fara sa atinga firewall-ul
    real al masinii pe care ruleaza testele"""

    def __init__(
        self,
        add_rule: Callable[[str], None],
        remove_rule: Callable[[str], None],
        default_duration: timedelta = DEFAULT_BLOCK_DURATION,
        max_history: int = DEFAULT_MAX_HISTORY,
    ) -> None:
        self._add_rule = add_rule
        self._remove_rule = remove_rule
        self._default_duration = default_duration
        self._max_history = max_history
        self._blocked: dict[str, BlockedIp] = {}
        self._timers: dict[str, threading.Timer] = {}
        self._history: list[BlockHistoryEntry] = []
        self._lock = threading.Lock()

    def block(
        self, ip: str, reason: str, duration: timedelta | None = None
    ) -> BlockedIp:
        duration = duration or self._default_duration
        with self._lock:
            existing = self._blocked.get(ip)
            if existing is not None:
                return existing

            try:
                self._add_rule(ip)
            except Exception as exc:
                raise BlockRuleError(f"nu s-a putut bloca {ip}: {exc}") from exc

            now = datetime.now()
            entry = BlockedIp(ip=ip, reason=reason, blocked_at=now, expires_at=now + duration)
            self._blocked[ip] = entry

            self._history.append(
                BlockHistoryEntry(
                    ip=ip, reason=reason, blocked_at=now, expires_at=now + duration
                )
            )
            if len(self._history) > self._max_history:
                self._history.pop(0)

            timer = threading.Timer(duration.total_seconds(), self._expire, args=(ip,))
            timer.daemon = True
            timer.start()
            self._timers[ip] = timer

            return entry

    def unblock(self, ip: str) -> None:
        with self._lock:
            self._unblock_locked(ip, ended_by="manual")

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked

    def active_blocks(self) -> list[BlockedIp]:
        with self._lock:
            return list(self._blocked.values())

    def history(self) -> list[BlockHistoryEntry]:
        """toate blocarile din aceasta sesiune, active sau incheiate deja
        (nu se pierde din vedere o blocare doar pentru ca a expirat -
        vezi ResponsePanel). NU e persistat pe disc - se reseteaza la
        fiecare pornire a aplicatiei, la fel ca starea BlockManager
        insasi (spre deosebire de Loguri, care ramane permanent)"""
        with self._lock:
            return list(self._history)

    def shutdown(self) -> None:
        """elimina TOATE regulile active (nu doar opreste timerele) -
        altfel un timer neterminat moare odata cu procesul si regula de
        firewall ar ramane activa la nesfarsit, incalcand principiul
        "niciodata permanent". apelat la inchiderea aplicatiei"""
        with self._lock:
            for ip in list(self._blocked):
                self._unblock_locked(ip, ended_by="oprire aplicatie")

    def _expire(self, ip: str) -> None:
        with self._lock:
            self._unblock_locked(ip, ended_by="expirat")

    def _unblock_locked(self, ip: str, ended_by: str) -> None:
        if ip not in self._blocked:
            return
        timer = self._timers.pop(ip, None)
        if timer is not None:
            timer.cancel()
        try:
            self._remove_rule(ip)
        except Exception:
            # best-effort: un IP ramas "blocat" fara nicio cale de a-l
            # debloca din UI (pentru ca am refuzat sa curatam starea
            # interna) e mai rau decat o regula de firewall care ramane
            # (userul poate oricum sa o stearga manual din netsh/OS). in
            # plus asta ruleaza si din thread-ul de expirare si din
            # shutdown() - o exceptie aici nu trebuie sa opreasca restul
            pass
        del self._blocked[ip]

        now = datetime.now()
        for entry in reversed(self._history):
            if entry.ip == ip and entry.unblocked_at is None:
                entry.unblocked_at = now
                entry.ended_by = ended_by
                break
