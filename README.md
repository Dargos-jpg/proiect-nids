# Hybrid NIDS

A Network Intrusion Detection System that combines signature-based
detection with two machine learning models that check each other.

## architecture

```
packet capture (live or PCAP)
        |
   parsing + metadata extraction
        |
   +----+----+
   |         |
signatures   ML features
   |         |
 match?   expert model + local model
   |         |
   +----+----+
        |
   event (severity, type, source)
        |
   live dashboard
        |
   automatic response (opt-in, safe/reversible)
   or manual response (human-in-the-loop)
        |
   logging + audit trail
```

Full architecture details and design decisions are in
[CONTEXT-nids.md](CONTEXT-nids.md) (Romanian).

## project structure

```
nids/
  capture/    live/PCAP packet capture, metadata extraction (Scapy)
  signatures/ rule-based detection (port scan with an optional time
              window, sensitive ports such as SSH/RDP/SMB)
  ml/
    expert/   model pre-trained on a public dataset (NSL-KDD)
    local/    model trained only on this network's own traffic
              (Isolation Forest, continuous incremental training)
    features/ feature extraction from packets/connections
  core/       orchestration, event model, model-agreement logic, settings
  response/   safe/reversible response actions (temporary IP block via
              Windows Firewall, manual or automatic)
  storage/    event persistence and audit trail (SQLite)
  ui/         PySide6 desktop interface
tests/        unit/integration tests
data/
  raw/        public datasets (NSL-KDD etc.), not tracked in git
  models/     trained models saved locally, not tracked in git
scripts/      utility scripts (train the expert model)
docs/         additional documentation
```

## key features

- live packet capture (Scapy/Npcap) and PCAP file analysis
- signature-based detection: port scanning (with an optional time
  window) and access to a configurable list of sensitive ports
- two independent ML models instead of a single classifier:
  - an expert model (Random Forest) pre-trained on NSL-KDD
  - a local model (Isolation Forest) trained continuously on this
    network's own traffic, with a sliding window and periodic retraining
  - disagreement between the two models is treated as a signal, not
    just averaged away
- explainability for every flagged connection: feature importance,
  deviation from the learned baseline, rare categorical combinations,
  and a continuous anomaly score
- configurable detection sensitivity, training/retraining cadence, and
  reporting strictness, adjustable from the UI without touching code
- safe, reversible incident response: temporary IP blocking, always
  auto-expiring, triggered manually or automatically (opt-in, high
  confidence cases only), with a full audit history
- dockable dark-themed desktop UI: live traffic chart, searchable
  traffic/log views, on-demand connection inspection, HTML report export

## installation

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## running

```
python -m nids.ui.main
```

Live packet capture requires administrator/root privileges. Blocking an
IP address (Windows Firewall) also requires administrator privileges.

## status

Actively developed, built incrementally. See [NOTES.md](NOTES.md) for
progress and technical notes (Romanian).
