# NIDS hibrid

Sistem de detectie a intruziunilor in retea (Network Intrusion Detection
System). Combina detectie bazata pe semnaturi cu doua modele de machine
learning care se completeaza reciproc.

## arhitectura

```
captura pachete (live sau PCAP)
        |
   parsare + extragere metadate
        |
   +----+----+
   |         |
semnaturi   features ML
   |         |
 match?   model expert + model local
   |         |
   +----+----+
        |
   eveniment (severitate, tip, sursa)
        |
   dashboard live
        |
   raspuns automat (safe/reversibil) sau manual
        |
   logging + audit trail
```

Detaliile complete de arhitectura si deciziile de design sunt in
[CONTEXT-nids.md](CONTEXT-nids.md).

## structura proiect

```
nids/
  capture/    captura pachete live/PCAP, extragere metadate (Scapy)
  signatures/ detectie bazata pe reguli (port scan, brute-force, ARP spoofing, DNS tunneling)
  ml/
    expert/   model pre-antrenat pe dataset public (NSL-KDD / CICIDS2017)
    local/    model antrenat doar pe traficul retelei proprii
    features/ extragere features din pachete/fluxuri
  core/       orchestrare, model eveniment, cronologie incident
  response/   actiuni de raspuns safe/reversibile (block IP temporar, rate limit)
  storage/    persistenta evenimente, logging, audit trail
  ui/         interfata desktop PySide6
tests/        teste unitare
data/
  raw/        dataset-uri publice (NSL-KDD etc.), nu intra in git
  models/     modele antrenate salvate local, nu intra in git
scripts/      scripturi utilitare (antrenare model expert, generare date demo)
docs/         documentatie suplimentara
```

## instalare

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## rulare

```
python -m nids.ui.main
```

Captura de pachete live necesita drepturi de administrator/root.

## status

proiect in dezvoltare, construit incremental. vezi [NOTES.md](NOTES.md)
pentru progres si urmatorii pasi.
