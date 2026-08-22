from __future__ import annotations

from enum import Enum

from nids.core.event import Event, Severity


class Agreement(Enum):
    """vezi CONTEXT-nids.md - dezacordul dintre modele e semnal util,
    nu doar vot majoritar"""

    BOTH_ATTACK = "ambele modele de acord: atac"
    BOTH_NORMAL = "ambele modele de acord: normal"
    EXPERT_ONLY = "doar modelul expert semnaleaza"
    LOCAL_ONLY = "doar modelul local semnaleaza"
    LOCAL_LEARNING = "model local inca in modul invatare"


def combine_predictions(expert_pred: int, local_pred: int | None) -> Agreement:
    """expert_pred/local_pred: 0=normal, 1=atac/anomalie.
    local_pred=None cand modelul local e inca in modul invatare (cold
    start), nu poate confirma sau infirma inca"""
    if local_pred is None:
        return Agreement.LOCAL_LEARNING
    if expert_pred == 1 and local_pred == 1:
        return Agreement.BOTH_ATTACK
    if expert_pred == 0 and local_pred == 0:
        return Agreement.BOTH_NORMAL
    if expert_pred == 1 and local_pred == 0:
        return Agreement.EXPERT_ONLY
    return Agreement.LOCAL_ONLY


def event_for_agreement(
    agreement: Agreement, src_ip: str, dst_ip: str, expert_pred: int
) -> Event | None:
    """None cand nu e nimic de raportat (trafic normal confirmat, sau
    model local inca invata + expert nu vede nimic)"""
    if agreement is Agreement.BOTH_NORMAL:
        return None

    if agreement is Agreement.BOTH_ATTACK:
        return Event(
            event_type="atac (ambele modele de acord)",
            source_ip=src_ip,
            severity=Severity.HIGH,
            description=(
                f"modelul expert si modelul local sunt de acord: traficul catre "
                f"{dst_ip} pare un atac - incredere mare"
            ),
        )

    if agreement is Agreement.LOCAL_ONLY:
        return Event(
            event_type="anomalie noua (doar model local)",
            source_ip=src_ip,
            severity=Severity.HIGH,
            description=(
                f"modelul local considera anormal traficul catre {dst_ip}, dar "
                f"modelul expert nu recunoaste niciun pattern cunoscut - posibil "
                f"atac nou sau comportament neobisnuit specific retelei tale"
            ),
        )

    if agreement is Agreement.EXPERT_ONLY:
        return Event(
            event_type="posibil fals-pozitiv (doar model expert)",
            source_ip=src_ip,
            severity=Severity.MEDIUM,
            description=(
                f"modelul expert semnaleaza traficul catre {dst_ip} ca atac, dar "
                f"modelul local il considera normal pentru reteaua ta - posibil "
                f"fals-pozitiv, merita verificat manual"
            ),
        )

    # LOCAL_LEARNING
    if expert_pred == 0:
        return None
    return Event(
        event_type="atac cunoscut (model local inca invata)",
        source_ip=src_ip,
        severity=Severity.MEDIUM,
        description=(
            f"modelul expert semnaleaza traficul catre {dst_ip} ca atac. "
            f"modelul local e inca in modul de invatare, nu poate confirma "
            f"sau infirma inca"
        ),
    )
