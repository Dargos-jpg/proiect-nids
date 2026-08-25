from __future__ import annotations

from nids.capture.pcap_reader import read_pcap
from nids.core.analysis import event_from_port_scan
from nids.core.event import Event
from nids.core.ml_combination import combine_predictions, event_for_agreement
from nids.ml.expert.model import ExpertModel
from nids.ml.expert.predict import predict_connections
from nids.ml.features.nsl_kdd_style import extract_nsl_kdd_style_features
from nids.ml.local.model import LocalModel
from nids.signatures.port_scan import DEFAULT_PORT_THRESHOLD, detect_port_scans
from nids.signatures.sensitive_ports import detect_sensitive_port_contacts, event_from_sensitive_port


def analyze_pcap_hybrid(
    path: str,
    expert: ExpertModel,
    port_scan_threshold: int = DEFAULT_PORT_THRESHOLD,
    port_scan_window: float | None = None,
    sensitive_ports: set[int] | None = None,
) -> list[Event]:
    """analizeaza un PCAP cu toate cele trei mecanisme din context:
    semnaturi (port scan), model expert (pre-antrenat pe NSL-KDD) si
    model local. pentru un fisier static, modelul local se antreneaza
    chiar pe traficul din acest fisier - e modul standard de folosire a
    unui Isolation Forest pe un set de date static (gaseste ce iese in
    evidenta fata de restul fisierului), nu cere cold start ca la
    monitorizarea live, unde nu exista inca "restul fisierului" """
    packets = read_pcap(path)

    events = [
        event_from_port_scan(scan)
        for scan in detect_port_scans(
            packets, threshold=port_scan_threshold, window_seconds=port_scan_window
        )
    ]
    events.extend(
        event_from_sensitive_port(evt)
        for evt in detect_sensitive_port_contacts(packets, sensitive_ports or set())
    )

    records = extract_nsl_kdd_style_features(packets)
    if not records:
        return events

    expert_predictions = predict_connections(expert, records)
    local_model = LocalModel.train(records)
    local_predictions = local_model.predict(records)

    for record, expert_pred, local_pred in zip(records, expert_predictions, local_predictions):
        agreement = combine_predictions(expert_pred, local_pred)
        event = event_for_agreement(agreement, record.src_ip, record.dst_ip, expert_pred)
        if event is not None:
            event.dest_ip = record.dst_ip
            event.src_port = record.src_port
            event.dest_port = record.dst_port
            event.protocol = record.protocol_type
            events.append(event)

    return events
