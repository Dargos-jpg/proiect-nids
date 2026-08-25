from __future__ import annotations

from dataclasses import dataclass
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


# event_type-ul exact folosit de describe_agreement() pentru BOTH_ATTACK -
# constanta publica, nu doar text inline, ca sa aiba DashboardPanel un
# criteriu stabil de verificat pentru blocarea automata ("doar cand
# ambele modele sunt de acord"), fara sa duplice logica de combinare
BOTH_ATTACK_EVENT_TYPE = "atac (ambele modele de acord)"


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


@dataclass
class AgreementDescription:
    event_type: str
    description: str
    severity: Severity | None  # None = nu genereaza eveniment automat, dar tot descriptiv


def describe_agreement(
    agreement: Agreement, dst_ip: str, expert_pred: int
) -> AgreementDescription:
    """text descriptiv pentru ORICE combinatie, inclusiv "totul e normal"
    - spre deosebire de event_for_agreement, care omite tacut cazurile
    neinteresante. folosit la inspectia manuala a unei conexiuni, unde
    userul vrea sa vada raspunsul chiar si cand nu s-a intamplat nimic"""
    if agreement is Agreement.BOTH_NORMAL:
        return AgreementDescription(
            event_type="trafic normal (ambele modele de acord)",
            description=(
                f"modelul expert si modelul local sunt de acord: traficul catre "
                f"{dst_ip} pare normal"
            ),
            severity=None,
        )

    if agreement is Agreement.BOTH_ATTACK:
        return AgreementDescription(
            event_type=BOTH_ATTACK_EVENT_TYPE,
            description=(
                f"modelul expert si modelul local sunt de acord: traficul catre "
                f"{dst_ip} pare un atac - incredere mare"
            ),
            severity=Severity.HIGH,
        )

    if agreement is Agreement.LOCAL_ONLY:
        return AgreementDescription(
            event_type="anomalie noua (doar model local)",
            description=(
                f"modelul local considera anormal traficul catre {dst_ip}, dar "
                f"modelul expert nu recunoaste niciun pattern cunoscut - posibil "
                f"atac nou sau comportament neobisnuit specific retelei tale"
            ),
            severity=Severity.HIGH,
        )

    if agreement is Agreement.EXPERT_ONLY:
        return AgreementDescription(
            event_type="posibil fals-pozitiv (doar model expert)",
            description=(
                f"modelul expert semnaleaza traficul catre {dst_ip} ca atac, dar "
                f"modelul local il considera normal pentru reteaua ta - posibil "
                f"fals-pozitiv, merita verificat manual"
            ),
            severity=Severity.MEDIUM,
        )

    # LOCAL_LEARNING
    if expert_pred == 0:
        return AgreementDescription(
            event_type="normal (model local inca invata)",
            description=(
                f"modelul expert nu vede nimic suspect in traficul catre {dst_ip}. "
                f"modelul local e inca in modul de invatare, nu poate confirma "
                f"independent inca"
            ),
            severity=None,
        )
    return AgreementDescription(
        event_type="atac cunoscut (model local inca invata)",
        description=(
            f"modelul expert semnaleaza traficul catre {dst_ip} ca atac. "
            f"modelul local e inca in modul de invatare, nu poate confirma "
            f"sau infirma inca"
        ),
        severity=Severity.MEDIUM,
    )


# praguri euristice pe scorul de anomalie al modelului local (vezi
# LocalModel.anomaly_score - mai mare = mai anormal, 0 e granita de
# decizie folosita si de predict()/contamination). nu sunt calibrate
# statistic (Isolation Forest nu are o scala universala intre seturi de
# date diferite), doar o impartire rezonabila in 3 trepte pentru
# severitate graduala in loc de "mereu HIGH" cand modelul local flagheaza
SEVERE_SCORE_THRESHOLD = 0.15
MODERATE_SCORE_THRESHOLD = 0.05


def severity_from_local_score(score: float) -> Severity:
    """publica (nu doar interna) - reutilizata si de ConnectionInspectorDialog
    pentru eticheta afisata langa scorul brut, ca sa nu existe doua surse
    de adevar pentru aceleasi praguri"""
    if score >= SEVERE_SCORE_THRESHOLD:
        return Severity.HIGH
    if score >= MODERATE_SCORE_THRESHOLD:
        return Severity.MEDIUM
    return Severity.LOW


def event_for_agreement(
    agreement: Agreement,
    src_ip: str,
    dst_ip: str,
    expert_pred: int,
    strict: bool = False,
    local_anomaly_score: float | None = None,
) -> Event | None:
    """None cand nu e nimic de raportat (trafic normal confirmat, sau
    model local inca invata + expert nu vede nimic). strict=True (setare
    din MlPanel) inseamna "raporteaza doar cand ambele modele sunt de
    acord" - suprima EXPERT_ONLY/LOCAL_ONLY/LOCAL_LEARNING (posibile
    fals-pozitive ale unui singur model), pastreaza doar BOTH_ATTACK.

    local_anomaly_score (scorul continuu, nu doar binarul predict()) -
    daca e dat SI modelul local a contribuit la semnal (BOTH_ATTACK,
    LOCAL_ONLY), inlocuieste severitatea FIXA din describe_agreement()
    cu una graduala (usor/moderat/sever) - userul a semnalat ca "mereu
    HIGH" pentru orice flag local face jurnalul greu de prioritizat.
    EXPERT_ONLY/LOCAL_LEARNING raman neschimbate - nu exista un scor
    local de gradat acolo (modelul local nu a confirmat nimic)"""
    described = describe_agreement(agreement, dst_ip, expert_pred)
    if described.severity is None:
        return None
    if strict and agreement is not Agreement.BOTH_ATTACK:
        return None

    severity = described.severity
    if local_anomaly_score is not None and agreement in (
        Agreement.BOTH_ATTACK,
        Agreement.LOCAL_ONLY,
    ):
        severity = severity_from_local_score(local_anomaly_score)

    return Event(
        event_type=described.event_type,
        source_ip=src_ip,
        severity=severity,
        description=described.description,
    )
