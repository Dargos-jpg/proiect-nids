# Hybrid NIDS

A Network Intrusion Detection System that combines signature-based
detection with two **independent, in-parallel** machine learning
pipelines that check each other — one trained on the classic NSL-KDD
dataset (1998-99), one on the modern CSE-CIC-IDS2018 dataset — plus a
honeypot that feeds real attack traffic back into continuous retraining.

## architecture

```
packet capture (live or PCAP)
        |
   parsing + metadata extraction
        |
   +----+-----------------+
   |                       |
signatures            ML features
(port scan, brute-force,   |
 ARP spoofing, DNS      +--+----------------------+
 tunneling, payload      |                        |
 patterns, sensitive   legacy pipeline        modern pipeline
 ports)                (NSL-KDD: expert +     (CSE-CIC-IDS2018: expert +
   |                    local model)           local model) -- PRIMARY
   |                       |                        |
   |                  "second opinion"      drives detection/auto-block
   |                       |                        |
   +-----------------------+------------------------+
                            |
                    event (severity, type, source)
                            |
              live dashboard (traffic, protocol, top
              talkers, model-comparison charts)
                            |
              automatic response (opt-in, safe/reversible)
              or manual response (human-in-the-loop)
                            |
              logging + audit trail (SQLite)
                            |
              honeypot hits -> continuous local-model retraining
```

Full architecture details and design decisions are in
[CONTEXT-nids.md](CONTEXT-nids.md); the legacy-vs-modern dataset study
(why two pipelines, how each was built and compared) is in
[DATASET-COMPARISON.md](DATASET-COMPARISON.md) (Romanian).

## project structure

```
nids/
  capture/    live/PCAP packet capture, metadata extraction (Scapy)
  signatures/ rule-based detection: port scan, brute-force, ARP spoofing,
              DNS tunneling, known payload patterns, sensitive ports
  ml/
    expert/   legacy expert model, pre-trained on NSL-KDD (1998-99)
    local/    legacy local model, trained only on this network's own
              traffic (Isolation Forest, continuous incremental training)
    modern/   modern expert + local model pair, trained on
              CSE-CIC-IDS2018 (2018) - the PRIMARY detection pipeline
    features/ feature extraction from packets/connections (both schemas)
  honeypot/   fake-service listener that collects real attacker
              interactions and feeds them back into local-model retraining
  scanner/    active vulnerability scan (open ports, banner grab, known
              protocol-level risk notes)
  core/       orchestration, event model, model-agreement logic, DNS/ASN
              lookups, settings
  response/   safe/reversible response actions (temporary IP block via
              Windows Firewall, manual or automatic)
  storage/    event persistence and audit trail (SQLite)
  ui/         PySide6 desktop interface (dashboard, charts, forensics,
              honeypot/scanner panels, connection/event inspection)
tests/        660+ unit/integration tests
data/
  raw/        public datasets (NSL-KDD, CSE-CIC-IDS2018 samples), not
              tracked in git
  models/     trained models saved locally, not tracked in git
scripts/      dataset preparation and model training utilities
docs/         additional documentation
```

## key features

- live packet capture (Scapy/Npcap) and PCAP file analysis
- signature-based detection: port scanning, brute-force attempts, ARP
  spoofing, DNS tunneling, known payload patterns, and a configurable
  list of sensitive ports
- **two independent ML pipelines running in parallel**, trained on two
  different datasets 20 years apart (NSL-KDD vs CSE-CIC-IDS2018), each
  built the same way (expert model + continuously-trained local model):
  - the modern (2018) pipeline is primary and drives detection/auto-block
  - the legacy (1998-99) pipeline runs alongside as a "second opinion"
    and continues training in the background
  - within each pipeline, disagreement between the expert and local
    model is treated as a signal, not just averaged away
  - a dedicated dashboard view compares verdicts between the two
    pipelines on the same live traffic
- honeypot with fake service banners that collects real attacker
  interactions and continuously retrains the local model on genuine
  attack traffic, not just synthetic data
- active vulnerability scanner: open-port discovery, banner grabbing,
  and protocol-level risk notes (e.g. unencrypted protocols, known
  historical exploits)
- packet-level forensics: reconstruct the full raw packet-by-packet
  timeline of any connection, independent of the ML models
- reverse-DNS and AS/organization/country/BGP-prefix lookups (PTR +
  Team Cymru) to identify who a given IP address actually belongs to
- explainability for every flagged connection: feature importance,
  deviation from the learned baseline, rare categorical combinations,
  and a continuous anomaly score
- configurable detection sensitivity, training/retraining cadence, and
  reporting strictness, adjustable from the UI without touching code
- safe, reversible incident response: temporary IP blocking, always
  auto-expiring, triggered manually or automatically (opt-in, high
  confidence cases only), with a full audit history
- dockable dark-themed desktop UI: live multi-view traffic dashboard
  (packets/s, bytes/s, protocol distribution, top talkers, model
  comparison), searchable traffic/log views, on-demand connection
  inspection, HTML report export

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

Preparing the modern (CSE-CIC-IDS2018) dataset and training its expert
model is done separately, via `scripts/prepare_cse_cic_ids2018.py` and
`scripts/train_modern_expert_model.py` - see
[DATASET-COMPARISON.md](DATASET-COMPARISON.md). The app runs fine
without this step; the modern pipeline is simply unavailable until a
trained model exists.

## status

Actively developed, built incrementally, 660+ automated tests. See
[NOTES.md](NOTES.md) for progress/technical notes and
[BUGS.md](BUGS.md) for real bugs found during testing and their fixes
(both Romanian).
