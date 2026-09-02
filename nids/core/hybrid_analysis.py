from __future__ import annotations

from nids.capture.arp_meta import read_pcap_arp
from nids.capture.dns_meta import read_pcap_dns_queries
from nids.capture.pcap_reader import read_pcap
from nids.capture.payload_meta import read_pcap_payload_samples
from nids.core.analysis import event_from_port_scan
from nids.core.event import Event
from nids.core.ml_combination import combine_predictions, event_for_agreement
from nids.ml.expert.model import ExpertModel
from nids.ml.expert.predict import predict_connections
from nids.ml.features.nsl_kdd_style import extract_nsl_kdd_style_features
from nids.ml.local.model import LocalModel
from nids.signatures.arp_spoofing import detect_arp_spoofing, event_from_arp_spoof
from nids.signatures.brute_force import (
    DEFAULT_ATTEMPT_THRESHOLD,
    DEFAULT_WINDOW_SECONDS as DEFAULT_BRUTE_FORCE_WINDOW_SECONDS,
    detect_brute_force,
    event_from_brute_force,
)
from nids.signatures.dns_tunneling import (
    DEFAULT_MIN_ENTROPY,
    DEFAULT_MIN_LABEL_LENGTH,
    detect_dns_tunneling,
    event_from_dns_tunnel,
)
from nids.signatures.payload_signatures import detect_payload_signatures, event_from_payload_match
from nids.signatures.port_scan import DEFAULT_PORT_THRESHOLD, detect_port_scans
from nids.signatures.sensitive_ports import detect_sensitive_port_contacts, event_from_sensitive_port


def analyze_pcap_hybrid(
    path: str,
    expert: ExpertModel,
    port_scan_threshold: int = DEFAULT_PORT_THRESHOLD,
    port_scan_window: float | None = None,
    sensitive_ports: set[int] | None = None,
    brute_force_threshold: int = DEFAULT_ATTEMPT_THRESHOLD,
    brute_force_window: float = DEFAULT_BRUTE_FORCE_WINDOW_SECONDS,
    brute_force_ports: set[int] | None = None,
    dns_min_label_length: int = DEFAULT_MIN_LABEL_LENGTH,
    dns_min_entropy: float = DEFAULT_MIN_ENTROPY,
    payload_signatures_enabled: bool = True,
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
    events.extend(
        event_from_brute_force(evt)
        for evt in detect_brute_force(
            packets,
            threshold=brute_force_threshold,
            window_seconds=brute_force_window,
            target_ports=brute_force_ports,
        )
    )
    events.extend(
        event_from_arp_spoof(evt) for evt in detect_arp_spoofing(read_pcap_arp(path))
    )
    events.extend(
        event_from_dns_tunnel(evt)
        for evt in detect_dns_tunneling(
            read_pcap_dns_queries(path),
            min_label_length=dns_min_label_length,
            min_entropy=dns_min_entropy,
        )
    )
    if payload_signatures_enabled:
        events.extend(
            event_from_payload_match(m)
            for m in detect_payload_signatures(read_pcap_payload_samples(path))
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
