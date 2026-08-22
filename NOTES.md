# notite dezvoltare

## decizii luate

- Python + scikit-learn + Scapy + PySide6 (nu C#/.NET, decizie deliberata)
- structura simpla, fara src-layout, fara pyproject/poetry - pachetul
  `nids/` sta direct la radacina, rulat cu `python -m nids.ui.main`
- venv + requirements.txt pentru dependinte, nimic mai complicat
- cele doua modele ML (expert + local) nu sunt ensemble clasic,
  dezacordul dintre ele e semnal, vezi CONTEXT-nids.md
- import scapy mereu cu `from scapy.all import ...`, nu din submodule
  (`scapy.utils` etc.) - importul partial nu inregistreaza layerele
  (Ether etc.) si rdpcap da warning fals "unknown LL type" + trateaza
  tot ca Raw
- pentru captura live: subclasare QThread direct (`run()` suprascris),
  NU worker QObject + moveToThread + `started.connect(worker.run)`.
  al doilea pattern e antipattern cand run() e un singur apel blocant de
  lunga durata (nu are nevoie de exec()) - a cauzat un bug real: dupa
  stop -> start din nou, thread-ul nou nu mai raporta nimic
- schema de features NSL-KDD (41 coloane) NU e aceeasi cu FlowFeatures
  simplu din nids/ml/features/flow.py (packet_count, total_bytes,
  duration...) - de-asta a fost construit separat un extractor
  compatibil (vezi mai jos, pasul 8 extins) pentru 28 din cele 41
- nids/ml/features/connection.py grupeaza pachetele pe CONEXIUNE
  (ambele directii impreuna, cheie normalizata pe perechea de capete),
  diferit de flow.py care grupeaza per DIRECTIE - necesar ca sa
  calculam corect src_bytes/dst_bytes, care descriu explicit cele doua
  directii ale aceleiasi conexiuni. cele doua module coexista, nu se
  inlocuiesc una pe alta
- "flag"-ul de stare al conexiunii (SF/S0/REJ/...) e o aproximare
  simplificata din flag-urile TCP observate, nu replica exact taxonomia
  originala NSL-KDD - la fel si TrafficWindowTracker (cele 19 features
  "traffic", fereastra de 2s + fereastra de 100 conexiuni per host) -
  taxonomia originala are ambiguitati documentate chiar si in
  reimplementari academice, am ales o interpretare proprie, consistenta,
  documentata in cod

## roadmap (treptat, fiecare pas trebuie sa ruleze la final)

1. [x] structura de proiect (foldere, config, entry point gol)
2. [x] UI schelet: fereastra principala cu tab-uri goale (Dashboard,
   Semnaturi, ML, Raspuns, Loguri)
3. [x] capture: citire PCAP static cu Scapy, extragere metadate de baza
   (IP, port, protocol, dimensiune, timing) - inainte de live capture,
   mai usor de testat
4. [x] signatures: prima regula simpla (port scan) pe metadatele extrase
5. [x] core: model de eveniment + afisare evenimente in dashboard (lista simpla)
6. [x] capture live (Scapy sniff) - functioneaza fara admin daca la
   instalarea Npcap ramane nebifat "Restrict driver's access to
   Administrators only"
   - [x] wired in Dashboard: buton Start/Stop monitorizare, ruleaza pe
     thread separat (QThread + semnale Qt), detectie incrementala cu
     StreamAnalyzer (alerta o singura data per sursa/destinatie, nu la
     fiecare pachet), oprire curata la inchiderea ferestrei
7. [x] ml/features: extragere features pentru ML din fluxuri (grupare pe
   5-tuple: src_ip, dst_ip, src_port, dst_port, protocol - nu per pachet
   individual, prea zgomotos pentru ML)
8. [x] ml/expert: Random Forest antrenat pe NSL-KDD (KDDTrain+/KDDTest+,
   descarcat de pe github.com/defcom17/NSL_KDD - sursa oficiala UNB nu
   mai serveste fisierele direct), clasificare binara (normal/atac),
   salvat cu joblib. Acuratete 76.77% pe KDDTest+ - normal, nu e bug:
   setul de test contine tipuri de atac care nu apar deloc in antrenare
   (deliberat, ca sa nu poti "trisa" prin memorare). exact asta motiveaza
   arhitectura dual-model: expert-ul rateaza atacuri complet noi, acolo
   intervine modelul local
   - [x] extractor de features compatibil cu 28 din cele 41 coloane
     NSL-KDD, derivat din pachetele noastre capturate: categoria
     "basic" completa (9 - nids/ml/features/connection.py, a necesitat
     extindere PacketMeta cu tcp_flags si is_fragmented) + categoria
     "traffic" completa (19 - nids/ml/features/traffic_window.py).
     ramase neacoperite: cele 13 "content" (necesita inspectie payload
     aplicatie - login-uri, comenzi shell pe Telnet/rlogin/FTP; traficul
     modern e criptat oricum, decizie: nu merita efortul). tot combinat
     in nids/ml/features/nsl_kdd_style.py::extract_nsl_kdd_style_features()
   - [x] REANTRENAT modelul expert doar pe cele 28 de coloane (nu toate
     41) - nids/ml/expert/nsl_kdd.py acum are ALL_FEATURE_COLUMNS (41,
     pentru citirea corecta a fisierului CSV) separat de FEATURE_COLUMNS
     (28, ce chiar intra in model). acuratete aproape neschimbata
     (77.71% fata de 76.77%) - cele 13 "content" eliminate erau oricum
     aproape mereu zero pentru majoritatea conexiunilor, adaugau zgomot
     nu semnal. acum modelul e CHIAR utilizabil pe traficul nostru:
     nids/ml/expert/predict.py::predict_connections() leaga
     extract_nsl_kdd_style_features() -> encode_features() -> model,
     testat end-to-end pe http.cap (clasifica corect trafic normal
     HTTP/DNS ca "normal")
   - modelul local (pasul 9) tot nu depinde de asta - se antreneaza de
     la zero pe features-urile noastre, fara nevoie de compatibilitate
9. [x] ml/local: Isolation Forest (nids/ml/local/model.py), antrenat
   DOAR pe traficul propriu, refoloseste acelasi schema de 28 features
   (encode_features comun cu modelul expert) - ca sa poata fi comparate
   direct la pasul 10. cold start rezolvat cu LocalModelManager
   (nids/ml/local/learning.py): modul "invatare" colecteaza fara sa
   marcheze nimic pana la MIN_TRAINING_SAMPLES (500 implicit, testabil
   cu prag mic), apoi antreneaza automat si trece in modul activ.
   NU face reantrenare periodica (concept drift ramas problema
   cunoscuta, neadresata inca - vezi sectiunea de mai jos)
10. [x] combinare semnaturi + expert + local, logica de dezacord:
    - nids/core/ml_combination.py: Agreement (enum) + combine_predictions()
      (logica pura, fara I/O) + event_for_agreement() (mapare pe
      severitate/mesaj). ambele modele de acord pe atac -> HIGH; doar
      local semnaleaza (expert nu recunoaste) -> HIGH, "posibil atac
      nou"; doar expert semnaleaza -> MEDIUM, "posibil fals-pozitiv";
      ambele de acord pe normal -> niciun eveniment
    - nids/core/hybrid_analysis.py::analyze_pcap_hybrid(): pentru un
      fisier PCAP static, antreneaza modelul local chiar pe traficul din
      acel fisier (mod standard de folosire Isolation Forest pe un set
      static - gaseste ce iese in evidenta fata de restul fisierului,
      fara cold start ca la live)
    - wired in Dashboard: "Incarca PCAP..." foloseste acum
      analyze_pcap_hybrid daca modelul expert exista pe disc, altfel
      fallback graceful la analyze_pcap (doar semnaturi) - util daca
      cineva claseaza repo-ul fara sa ruleze scripts/train_expert_model.py
11. [ ] response: block IP temporar (safe/reversibil) + actiuni manuale din UI
12. [ ] storage: persistenta evenimente + audit trail
13. [ ] features de diferentiere: explicabilitate, mod simulare, cronologie
    incident, prag sensibilitate, export raport

## probleme de anticipat (vezi si CONTEXT-nids.md)

fals-pozitive, trafic criptat, volum mare de trafic, concept drift,
feature extraction gresit, cold start model local, calibrare scoruri
