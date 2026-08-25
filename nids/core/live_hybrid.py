from __future__ import annotations

from nids.capture.packet_meta import PacketMeta
from nids.core.event import Event
from nids.core.inspect import ConnectionAssessment, assessment_to_json, format_explanation_snippet
from nids.core.ml_combination import combine_predictions, event_for_agreement
from nids.ml.expert.model import ExpertModel
from nids.ml.expert.predict import explain_connection, predict_connections
from nids.ml.features.nsl_kdd_style import NslKddStyleFeatures, extract_nsl_kdd_style_features
from nids.ml.local.learning import LocalModelManager

_ConnectionKey = tuple[str, int | None, str, int | None, str]


def _connection_key(record: NslKddStyleFeatures) -> _ConnectionKey:
    return (record.src_ip, record.src_port, record.dst_ip, record.dst_port, record.protocol_type)


class LiveHybridAnalyzer:
    """echivalentul lui analyze_pcap_hybrid, dar pentru trafic live -
    reevalueaza periodic (nu la fiecare pachet, prea costisitor) toate
    conexiunile observate pana acum in sesiune. modelul local trece prin
    acelasi ciclu de cold start (LocalModelManager) ca oriunde in
    aplicatie - la inceputul sesiunii doar colecteaza, marcheaza dupa ce
    a strans destule conexiuni.

    fiecare CONEXIUNE (identitate completa: ambele IP-uri, ambele
    porturi, protocol) e evaluata o singura data pe sesiune - odata
    raportata (sau confirmata normala), nu mai e reevaluata, ca sa nu
    inunde lista cu acelasi rezultat la fiecare tick. NU deduplica doar
    pe perechea de IP-uri - varianta initiala facea asta si insemna ca,
    odata evaluat un IP, orice conexiune ulterioara catre acelasi IP
    (alt port, alta sesiune) era ignorata complet - userul a semnalat ca
    e o problema reala (un IP suspect a doua oara nu mai era vazut deloc)

    limitare cunoscuta: pastreaza toate pachetele sesiunii in memorie si
    le reproceseaza integral la fiecare tick (creste cu volumul de trafic
    - vezi "volum mare de trafic" in problemele anticipate din context)"""

    def __init__(
        self,
        expert: ExpertModel | None,
        local_manager: LocalModelManager,
        strict_reporting: bool = False,
    ) -> None:
        self._expert = expert
        self.local_manager = local_manager
        self._strict_reporting = strict_reporting
        self._packets: list[PacketMeta] = []
        self._evaluated_connections: set[_ConnectionKey] = set()

    def add_packet(self, pkt: PacketMeta) -> None:
        self._packets.append(pkt)

    def evaluate(self) -> list[Event]:
        if self._expert is None or not self._packets:
            return []

        records = extract_nsl_kdd_style_features(self._packets)
        new_records = [
            r for r in records if _connection_key(r) not in self._evaluated_connections
        ]
        if not new_records:
            return []

        expert_predictions = predict_connections(self._expert, new_records)

        events: list[Event] = []
        for record, expert_pred in zip(new_records, expert_predictions):
            self._evaluated_connections.add(_connection_key(record))

            local_pred = self.local_manager.process(record)
            local_score = self.local_manager.anomaly_score(record)
            agreement = combine_predictions(expert_pred, local_pred)
            event = event_for_agreement(
                agreement,
                record.src_ip,
                record.dst_ip,
                expert_pred,
                strict=self._strict_reporting,
                local_anomaly_score=local_score,
            )
            if event is not None:
                event.dest_ip = record.dst_ip
                event.src_port = record.src_port
                event.dest_port = record.dst_port
                event.protocol = record.protocol_type

                expert_features = explain_connection(self._expert, record)
                local_deviations = self.local_manager.explain(record)
                local_rarities = self.local_manager.explain_categorical(record)

                # "poza" completa a analizei, salvata ACUM cat mai avem
                # totul la indemana - explanation e textul de baza
                # (inainte sa adaugam rezumatul compact la description mai
                # jos), ca sa arate identic cu ce ar produce assess_connection()
                # daca ar fi apelat pe loc, din Trafic
                assessment = ConnectionAssessment(
                    record=record,
                    expert_prediction=expert_pred,
                    expert_top_features=expert_features,
                    local_prediction=local_pred,
                    local_is_learning=self.local_manager.is_learning,
                    local_anomaly_score=local_score,
                    local_deviations=local_deviations,
                    local_categorical_rarities=local_rarities,
                    agreement=agreement,
                    event_type=event.event_type,
                    explanation=event.description,
                )
                event.assessment_json = assessment_to_json(assessment)

                detail = format_explanation_snippet(expert_features, local_deviations, local_rarities)
                if detail:
                    event.description = f"{event.description} | {detail}"

                events.append(event)

        return events

    def reset(self) -> None:
        self._packets = []
        self._evaluated_connections = set()
