from __future__ import annotations

from collections import Counter, deque

from nids.capture.packet_meta import PacketMeta
from nids.core.event import Event
from nids.core.inspect import format_explanation_snippet
from nids.core.ml_combination import Agreement, combine_predictions, event_for_agreement
from nids.ml.features.cicflow_style import CicFlowFeatures, extract_cicflow_features
from nids.ml.modern.inspect import ModernAssessment, modern_assessment_to_json
from nids.ml.modern.learning import ModernLocalModelManager
from nids.ml.modern.model import ModernExpertModel
from nids.ml.modern.predict import explain_flow, predict_flows

_FlowKey = tuple[str, int | None, str, int | None, str]


def _flow_key(record: CicFlowFeatures) -> _FlowKey:
    return (record.src_ip, record.src_port, record.dst_ip, record.dst_port, record.protocol)


# vezi nids.core.live_hybrid.MAX_BUFFERED_PACKETS - acelasi bug real, acelasi
# fix (BUGS.md): fara plafon, self._packets creste nelimitat, iar evaluate()
# reproceseaza tot la fiecare tick - cost patratic in timpul sesiunii. schema
# moderna (extract_cicflow_features) e chiar MAI costisitoare per pachet
# decat cea veche (segmentare activ/idle, statistici IAT), deci acest plafon
# conteaza aici la fel de mult, daca nu mai mult
MAX_BUFFERED_PACKETS = 20_000


class ModernLiveHybridAnalyzer:
    """echivalentul lui nids.core.live_hybrid.LiveHybridAnalyzer, pe
    schema/modelele MODERNE (CSE-CIC-IDS2018) - acelasi principiu de
    evaluare incrementala per sesiune (fiecare FLUX evaluat o singura
    data, dedup pe identitatea completa), refolosind ml_combination.py
    NESCHIMBAT (verificat schema-agnostic - Faza 5, vezi DATASET-COMPARISON.md).

    salveaza assessment_json la fel ca LiveHybridAnalyzer (vezi
    nids/ml/modern/inspect.py, modern_assessment_to_json) - "Analizeaza
    aceasta conexiune cu ML" pentru un eveniment generat aici functioneaza
    si dupa ce pachetele sesiunii curente nu mai exista (alta sesiune,
    aplicatia repornita)"""

    def __init__(
        self,
        expert: ModernExpertModel | None,
        local_manager: ModernLocalModelManager,
        strict_reporting: bool = False,
    ) -> None:
        self._expert = expert
        self.local_manager = local_manager
        self._strict_reporting = strict_reporting
        self._packets: deque[PacketMeta] = deque(maxlen=MAX_BUFFERED_PACKETS)
        self._evaluated_flows: set[_FlowKey] = set()
        # vezi LiveHybridAnalyzer.agreement_counts - folosit pentru
        # comparatia vechi-vs-modern (TrafficChartPanel, "Comparatie modele")
        self.agreement_counts: Counter[Agreement] = Counter()

    def add_packet(self, pkt: PacketMeta) -> None:
        self._packets.append(pkt)

    def evaluate(self) -> list[Event]:
        if self._expert is None or not self._packets:
            return []

        records = extract_cicflow_features(list(self._packets))
        new_records = [r for r in records if _flow_key(r) not in self._evaluated_flows]
        if not new_records:
            return []

        expert_predictions = predict_flows(self._expert, new_records)

        events: list[Event] = []
        for record, expert_pred in zip(new_records, expert_predictions):
            self._evaluated_flows.add(_flow_key(record))

            local_pred = self.local_manager.process(record)
            local_score = self.local_manager.anomaly_score(record)
            agreement = combine_predictions(expert_pred, local_pred)
            self.agreement_counts[agreement] += 1
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
                event.protocol = record.protocol

                expert_features = explain_flow(self._expert, record)
                local_deviations = self.local_manager.explain(record)
                local_rarities = self.local_manager.explain_categorical(record)

                # vezi LiveHybridAnalyzer.evaluate() - aceeasi "poza"
                # completa, salvata acum cat mai avem totul la indemana.
                # de la Faza 6, modelul modern e principalul care mai
                # salveaza assessment_json pentru evenimente live (vezi
                # DATASET-COMPARISON.md, "de facut in continuare" - acest
                # gol e acum inchis)
                assessment = ModernAssessment(
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
                event.assessment_json = modern_assessment_to_json(assessment)

                detail = format_explanation_snippet(expert_features, local_deviations, local_rarities)
                if detail:
                    event.description = f"{event.description} | {detail}"

                events.append(event)

        return events

    def reset(self) -> None:
        self._packets = deque(maxlen=MAX_BUFFERED_PACKETS)
        self._evaluated_flows = set()
