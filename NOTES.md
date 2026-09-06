# notite dezvoltare

bug-uri reale gasite de user in timpul testarii + fix-uri aplicate: vezi
BUGS.md (fisier separat, ca sa nu se piarda printre notele de
arhitectura/features de mai jos).

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
11. [x] response: block IP temporar (safe/reversibil) + actiuni manuale din UI
    - nids/response/block.py: add_block_rule/remove_block_rule - reguli
      Windows Firewall reale (netsh advfirewall), necesita admin
    - nids/response/manager.py: BlockManager - logica pura, backend-ul
      (add_rule/remove_rule) e injectat ca sa poata fi testat cu un fals,
      fara sa atinga firewall-ul real. auto-expirare cu threading.Timer;
      shutdown() la inchiderea aplicatiei ELIMINA toate regulile active
      (nu doar opreste timerele) - altfel o regula ar ramane blocata
      permanent daca aplicatia se inchide inainte de expirare, ceea ce ar
      incalca principiul "niciodata permanent"
    - nids/ui/widgets/response_panel.py: tabel cu blocarile active
      (IP, motiv, expira la) + buton de deblocare manuala. citeste
      BlockManager printr-un QTimer (poll la 1s), NU direct din
      threading.Timer-ul de expirare - acela ruleaza pe alt thread, iar
      widget-urile Qt nu pot fi atinse decat din thread-ul UI
    - Dashboard: click-dreapta pe un eveniment -> "Blocheaza IP sursa
      (temporar)" - actiune manuala, human-in-the-loop, cum era in context
    - NU am rulat blocarea reala (netsh) in timpul testarii/verificarii -
      modifica Windows Firewall-ul real si cere admin, nu ceva de facut
      fara sa fie userul constient. testele folosesc mereu un backend fals
12. [x] storage: persistenta evenimente + audit trail
    - nids/storage/event_store.py: EventStore (SQLite, un singur
      fisier `data/nids.db`, gitignored). thread-safe (lock propriu +
      check_same_thread=False)
    - wired in Dashboard: orice eveniment afisat (din PCAP sau live) se
      salveaza automat; blocarea manuala a unui IP genereaza si ea o
      intrare de audit ("blocare manuala")
    - panoul "Loguri" (placeholder pana acum) arata istoricul persistat,
      refresh automat la 2s (QTimer, ca sa apara intrarile noi din
      monitorizarea live fara actiune din partea userului)
    - NEFACUT inca: expirarea automata a unei blocari (din BlockManager,
      thread separat) nu genereaza o intrare de audit - doar blocarea
      manuala initiala e logata. gap cunoscut, nu blocant
    - nids/ui/widgets/traffic_panel.py (nou, neplanificat initial in
      roadmap, cerut de user dupa ce a testat): tab "Trafic" langa
      "Loguri" - arata traficul BRUT, pachet cu pachet (nu doar
      evenimentele/alertele ca Dashboard/Loguri). util ca userul sa vada
      cu ochii lui ca aplicatia proceseaza trafic chiar si cand nimic nu
      declanseaza o alerta. limitat la 500 randuri (altfel sesiuni lungi
      de monitorizare ar incetini UI-ul); la live insereaza sus (cele mai
      noi primele), la incarcare PCAP inlocuieste tot dintr-o data
13. [~] features de diferentiere (partial):
    - [x] prag de sensibilitate ajustabil vizual: panoul "Semnaturi"
      (placeholder pana acum) are un slider (2-20 porturi distincte),
      legat atat la analiza PCAP cat si la monitorizarea live
    - [x] ML in monitorizarea live (era cel mai mare gol ramas):
      nids/core/live_hybrid.py::LiveHybridAnalyzer - echivalentul lui
      analyze_pcap_hybrid, dar incremental. NU reevalueaza la fiecare
      pachet (prea costisitor) - un QTimer in DashboardPanel (5s) cere
      periodic evaluate(), care re-extrage toate conexiunile din
      pachetele sesiunii si evalueaza doar perechile (sursa,destinatie)
      inca neevaluate. MIN_TRAINING_SAMPLES redus de la 500 la 50 (500
      nerealist pentru o sesiune scurta de testare/demo)
    - [x] REVIZUIT dupa feedback user: modelul local NU mai reseteaza la
      fiecare sesiune (varianta initiala, ineficienta - userul a
      semnalat explicit). nids/ml/local/learning.py rescris:
      - buffer = fereastra glisanta (MAX_BUFFER_SIZE=2000 conexiuni),
        NU se goleste dupa prima antrenare
      - reantreneaza periodic (RETRAIN_EVERY_N_SAMPLES=25 conexiuni noi)
        cat timp e activ, nu ramane inghetat la primul model antrenat -
        fereastra glisanta = si raspunsul la concept drift (traficul
        vechi iese din fereastra cu timpul)
      - stare (model + buffer) persistata pe disc
        (data/models/local_model_state.joblib, gitignored) prin
        LocalModelManager.save()/load()/load_or_new(). DashboardPanel
        incarca la inceputul monitorizarii (load_or_new) si salveaza la
        oprire, daca modelul a iesit din modul invatare - continua
        antrenarea, nu reincepe de la zero
      - IMPORTANT ramane valabil: modelul local e complet separat de
        modelul expert (nu imprumuta nimic din NSL-KDD) - doar ACUM nu
        mai uita ce a invatat despre reteaua userului intre sesiuni
      - capcana de retinut: save()/load() rezolva calea implicita
        (DEFAULT_STATE_PATH) IN INTERIORUL metodei, nu ca valoare
        implicita de parametru - altfel monkeypatch in teste nu are
        efect (valoarea s-ar "inghetat" la momentul definirii functiei).
        toate testele care apeleaza _start_monitoring() trebuie sa
        monkeypatch-uiasca DEFAULT_STATE_PATH catre tmp_path, altfel ar
        citi/scrie calea reala de pe disc si ar deveni nedeterministe
    - [x] FIX dupa feedback user: LiveHybridAnalyzer deduplica initial
      doar pe (src_ip, dst_ip) - odata evaluat un IP, orice conexiune
      ulterioara catre acelasi IP (alt port, alta sesiune complet) era
      ignorata pentru tot restul monitorizarii live. userul a semnalat
      corect ca "pare rau sa nu mai vada deloc un IP dupa o suspiciune".
      NslKddStyleFeatures a capatat doua campuri noi (src_port, dst_port -
      identificare, nu features, excluse in to_feature_frame()) si
      deduplicarea foloseste acum identitatea completa a conexiunii
      (ambele IP-uri, ambele porturi, protocol), la fel ca extract_connections()
    - [x] panoul "ML" (placeholder pana acum): status informativ -
      model expert incarcat da/nu, model local in invatare
      (X/Y conexiuni) sau activ. citeste starea din DashboardPanel prin
      polling (QTimer), acelasi pattern ca Loguri/Raspuns
    - [x] panoul "Trafic" (nou, neplanificat initial in roadmap, cerut
      de user dupa ce a testat monitorizarea live si s-a asteptat sa
      vada tot traficul, nu doar alertele): tab langa "Loguri" - arata
      traficul BRUT, pachet cu pachet. limitat la 500 randuri; la live
      insereaza sus (cele mai noi primele), la incarcare PCAP inlocuieste
      tot dintr-o data
    - [x] mod simulare: nids/core/simulation.py::run_port_scan_simulation()
      - trimite conexiuni TCP scurte catre PROPRIUL IP din reteaua
      locala (nu 127.0.0.1 - loopback-ul nu trece prin interfata de
      retea reala, Npcap nu l-ar vedea). buton in Dashboard, ruleaza pe
      SimulationThread (QThread, ca sa nu blocheze UI-ul cateva secunde).
      cere ca monitorizarea live sa ruleze deja, altfel doar arata un hint
    - [x] grafic live cu pyqtgraph (nids/ui/widgets/traffic_chart.py) -
      decizia de stack initiala din context (pyqtgraph pentru date care
      se actualizeaza constant), nefolosita pana acum. TrafficChartPanel:
      linie cu pachete/secunda pe fereastra glisanta de 60s, + marcaje
      punctuale colorate dupa severitate cand apare un eveniment nou -
      util sa vezi vizual cand un varf de trafic coincide cu o alerta.
      DOAR pentru monitorizare live (PCAP-urile au timestamp-uri
      istorice, n-are sens pe un grafic "acum in timp real"). integrat
      direct in Dashboard (nu dock separat), intre bara de butoane si
      lista de evenimente - Dashboard ramane vederea centrala "la prima
      vedere" din arhitectura Unity-style
      - capcana prinsa de teste: pozitia "acum" pe axa X trebuie
        calculata din ultima valoare inregistrata (self._tick_x[-1]),
        NU din self._tick_count direct - acesta e deja incrementat
        inainte de redraw, ar fi dat un offset gresit de -1
    - [x] explicabilitate + inspectie la cerere (cerut de user: "vreau sa
      selectez un pachet din trafic si sa vad de ce (nu) da flag"):
      - ExpertModel.explain(): top features dupa feature_importances_
        din Random Forest, GRUPATE inapoi de la coloanele one-hot
        ("service_http" -> "service") ca sa fie pe intelesul omului.
        importanta e GLOBALA (a modelului, nu specifica conexiunii) -
        aproximare, nu explicatie exacta gen SHAP (dependinta noua
        nejustificata pentru scop)
      - LocalModelManager.explain(): Isolation Forest n-are feature
        importance nativ - aproximare DIY (fara nicio dependinta noua):
        z-score per feature fata de media/deviatia din bufferul curent.
        functioneaza si in modul invatare (buffer partial, tot spune ceva)
      - LocalModelManager.predict_only(): predictie FARA efecte
        secundare (nu modifica bufferul, nu declanseaza reantrenare) -
        distinct de process(), care e pentru fluxul normal automat
      - ml_combination.describe_agreement(): text descriptiv pentru
        ORICE combinatie, inclusiv "totul normal" (event_for_agreement
        omite tacut cazurile neinteresante, aici userul vrea raspuns
        mereu). event_for_agreement e acum un wrapper subtire peste asta
      - core/inspect.py::assess_connection(): leaga tot intr-un singur
        rezultat (ConnectionAssessment)
      - TrafficPanel: click-dreapta pe un rand -> "Analizeaza aceasta
        conexiune cu ML", emite semnalul analyze_requested(pkt)
      - DashboardPanel: pastreaza self._all_packets (tot istoricul
        sesiunii), la cerere re-deriva toate conexiunile si gaseste-o pe
        cea a pachetului selectat (in orice directie - un pachet poate fi
        raspunsul, nu doar cererea), deschide ConnectionInspectorDialog
        (non-modal, mai multe pot fi deschise simultan)
      - ConnectionInspectorDialog: verdict, explicatie, tabel cu top
        features (expert), tabel cu deviatii fata de normal (local),
        tabel cu toate cele 28 de valori - "assessment pe orice", cum a
        cerut userul
      - CAPCANA reala prinsa la testare: QMenu.exec() / dialog real nu
        se pot monkeypatch-ui fiabil pe clasele native Qt/PySide6 - o
        incercare de test a deschis un meniu REAL, vizibil pe ecranul
        userului, care astepta un click ce nu venea (1 test a durat 73s
        inainte sa se rezolve). fix: NU testa niciodata interactiunea
        QMenu.exec()/QDialog.exec() direct - extrage logica testabila in
        metode separate (_packet_at(), etc.) si testeaz-o pe alea, sau
        monkeypatch-uieste explicit .show()/.exec() inainte de orice
        apel care ar putea afisa ceva real
    - [x] cronologie incident: EventStore.distinct_sources() +
      events_for_source() (cronologic, cele mai vechi primele - o
      naratiune). panoul "Loguri" are acum un filtru dupa sursa
      (QComboBox), pastreaza selectia userului la refresh automat
    - [x] export raport: nids/core/report.py::generate_html_report() -
      HTML de sine statator (fara CSS/JS extern), cu numaratoare pe
      severitate + tabel complet, escapare HTML corecta (nu e o
      problema reala de securitate aici, dar practica buna oricum).
      buton "Exporta raport HTML..." in Loguri - exporta ce e filtrat
      curent (toate sursele, sau doar cronologia sursei selectate)

roadmap-ul din context e acum complet acoperit (pasii 1-13). ramane
doar polish/imbunatatiri pe ce exista, discutate separat cu userul

## imbunatatiri post-roadmap (discutate cu userul dupa ce a inceput testarea)

- descrierile evenimentelor generate de ML in monitorizarea live sunt
  acum ENRICHED cu motivul concret: nids/core/inspect.py::format_explanation_snippet()
  ia top features de la ExpertModel.explain() si deviatiile notabile
  (|z|>=1.0) de la LocalModelManager.explain(), le formateaza compact
  ("model expert vede: flag=S0 (15%) | model local vede: dst_bytes=0
  fata de normal ~1400, z=-12.3") si le adauga la Event.description
  INAINTE sa fie salvat/afisat - deci apar direct in Loguri, nu doar in
  dialogul de inspectie manuala. userul a cerut asta dupa ce modelul
  local a inceput sa dea flag des si a vrut sa vada "ce vede el fata de
  cel expert" fara sa dea click pe fiecare pachet in parte
  - momentan doar pentru fluxul LIVE (LiveHybridAnalyzer) - analyze_pcap_hybrid
    (PCAP static) nu are inca aceeasi imbogatire a textului din descriere,
    ar fi nevoie de o abordare similara acolo daca se cere (are totusi
    acum identitatea conexiunii salvata, vezi mai jos)

- [x] explicabilitate CATEGORICA pentru modelul local (userul a cerut
  "cat mai complex", si a descoperit singur limitarea uitandu-se la un
  caz real: trafic UDP catre 239.255.255.250:1900 - SSDP/UPnP discovery,
  benign dar rar - marcat ATAC/ANOMALIE desi niciun z-score numeric nu
  era mare). motivul: Isolation Forest vede TOATE cele 28 de features
  (inclusiv cele categorice encodate one-hot: protocol_type, service,
  flag), dar explain() arata doar cele 9 numerice - o combinatie
  categorica rara (protocol+serviciu neobisnuit) putea fi motivul real,
  invizibil in explicatie. adaugat:
  - LocalModelManager.explain_categorical(): frecventa (0.0-1.0) fiecarei
    valori categorice (protocol_type/service/flag) in bufferul curent -
    frecventa mica = combinatie rara
  - ConnectionAssessment.local_categorical_rarities + tabel nou in
    ConnectionInspectorDialog
  - format_explanation_snippet() include acum si combinatiile rare
    (frecventa <10%) in descrierea din Loguri, nu doar deviatiile numerice

## analiza ML completa din Loguri + cautare/filtrare (cerute de user dupa ce a vazut evenimente reale in Loguri)

user: "in trafic sa stam sa cautam ar fi complicat [...] adaugam si niste
filtre de cautare in trafic si in loguri" - Loguri e unde se vad de fapt
problemele, nu are sens sa ceri userului sa gaseasca pachetul exact in
Trafic doar ca sa deschida analiza ML.

- **Event** (nids/core/event.py) are acum 4 campuri noi, toate opționale
  (default None) ca sa nu strice apelurile existente care nu le seteaza:
  dest_ip, src_port, dest_port, protocol - identitatea completa a
  conexiunii, nu doar source_ip ca inainte
- **EventStore** (nids/storage/event_store.py) persista aceste campuri -
  schema SQLite migrata cu ALTER TABLE (nu recreare), ca sa nu se piarda
  istoricul deja salvat de user pe disc la upgrade (data/nids.db nu e in
  git). _migrate() verifica PRAGMA table_info si adauga doar coloanele
  lipsa
- LiveHybridAnalyzer si analyze_pcap_hybrid populeaza acum aceste campuri
  pe orice Event generat de modelele ML (dest_ip/src_port/dest_port din
  record, protocol din record.protocol_type). evenimentele de port scan
  si cele de blocare manuala NU au aceasta identitate (nu corespund unei
  singure conexiuni ML) - raman cu dest_ip=None
- **LogsPanel** are acum:
  - camp de cautare libera (langa dropdown-ul de sursa) - filtreaza
    client-side (setRowHidden) pe toate coloanele afisate, nu doar sursa;
    se reaplica automat dupa fiecare refresh (la 2s) si la schimbarea
    textului
  - meniu contextual (click dreapta pe un rand) -> "Analizeaza aceasta
    conexiune cu ML", semnal nou `analyze_requested(StoredEvent)`
- **TrafficPanel** are acelasi tip de camp de cautare (IP sursa/destinatie,
  port, protocol - orice coloana), aplicat si la randuri noi (monitorizare
  live) si la load_packets (PCAP incarcat)
- **DashboardPanel** a fost refactorizat: fosta `_on_analyze_requested(pkt)`
  (doar pentru Trafic) a devenit `_analyze_connection(src_ip, src_port,
  dst_ip, dst_port, protocol)` - logica comuna de gasire+afisare, apelata
  fie din `_on_traffic_analyze_requested(pkt)`, fie din
  `_on_log_analyze_requested(entry)`. `_find_matching_connection()` a fost
  generalizata sa ia identitatea ca parametri separati, nu un PacketMeta
  - **limitare cunoscuta si asumata**: analiza completa (assess_connection)
    are nevoie de pachetele brute ale sesiunii curente (`self._all_packets`,
    care se goleste la fiecare Start monitorizare / PCAP nou incarcat) ca
    sa reconstruiasca cele 28 de features. un rand din Loguri dintr-o
    sesiune ANTERIOARA nu mai poate fi reanalizat complet - se afiseaza un
    mesaj clar in bara de status ("nu s-a putut identifica conexiunea..."),
    in loc sa dea eroare sau sa arate date gresite. explicatia compacta
    deja salvata in descriere (vezi sectiunea de mai sus) ramane insa
    vizibila oricand, indiferent de sesiune - doar tabelele detaliate
    (feature importance, z-score) cer date brute proaspete
  - evenimentele fara identitate de conexiune (port scan, blocare
    manuala) arata un mesaj dedicat ("acest eveniment nu are o conexiune
    ML asociata") in loc sa incerce o potrivire care nu poate reusi

- **rezolvata si limitarea de mai sus** (cross-sesiune): in loc sa
  reconstruim analiza din pachete brute (care nu mai exista dupa
  restart), salvam direct rezultatul COMPLET al analizei ca JSON, o
  singura data, in momentul in care evenimentul ML e creat -
  Event.assessment_json / coloana noua `assessment_json` in EventStore
  (acelasi tabel `events`, nicio tabela/fisier separat - mai simplu de
  intretinut si beneficiaza automat de aceeasi tranzactie SQLite)
  - nids/core/inspect.py::assessment_to_json()/assessment_from_json() -
    serializeaza/reconstruieste un ConnectionAssessment complet (record,
    predictii, toate cele 3 tabele). NU salveaza `agreement` (enum,
    nefolosit de dialog). predictiile vin din sklearn ca numpy.int64, nu
    json-serializabile direct - `default=_json_default` foloseste
    `.item()` pentru orice tip numpy intalnit, fara sa adauge numpy ca
    dependinta noua in acest fisier
  - LiveHybridAnalyzer construieste ConnectionAssessment-ul chiar in
    bucla de evaluare, refolosind explain_connection()/explain()/
    explain_categorical() deja calculate pentru textul din descriere -
    zero calcule in plus
  - DashboardPanel._on_log_analyze_requested(): daca `entry.assessment_json`
    exista, deschide dialogul DIRECT din el (assessment_from_json), fara
    sa mai caute in self._all_packets deloc - functioneaza in orice
    sesiune, oricat de veche. fallback pe mecanismul vechi (cautare in
    pachetele sesiunii curente) doar pentru evenimente vechi, salvate
    inainte de aceasta functionalitate (nu au assessment_json)
  - marime: ~2.5 KB JSON necomprimat per eveniment ML (masurat, nu doar
    estimat) - la 1000 de evenimente, sub 3 MB. nu justifica deduplicare
    sau vreo optimizare de spatiu; fiecare "duplicat" (aceeasi adresa
    flagata din nou, mai tarziu) e de fapt exact semnalul temporal util
    userului ("era flagged si data trecuta?"), nu risipa

## patru semnaturi noi: brute-force, ARP spoofing, DNS tunneling, payload malware

user a cerut "tot ce merita" din lista de semnaturi ramase din
CONTEXT-nids.md, plus explicit DNS tunneling + semnaturi malware in
payload (desi acestea doua au o limitare reala documentata clar, nu
ascunsa: functioneaza doar pe trafic NECRIPTAT).

**brute-force** (`nids/signatures/brute_force.py`) - acelasi tipar ca
port_scan.py (fereastra glisanta), dar numara porturi SURSA distincte
(incercari de conectare) catre ACELASI serviciu, nu porturi destinatie
distincte. `detect_brute_force()` (batch) + `BruteForceTracker` (live).
UI: prag, fereastra, porturi tinta editabile (implicit FTP/SSH/Telnet/RDP).

**ARP spoofing** (`nids/capture/arp_meta.py` + `nids/signatures/arp_spoofing.py`)
- prima semnatura care a cerut o cale de captura noua: ARP nu are strat
IP, era filtrat complet inainte (`if IP in pkt` in live_capture.py/
pcap_reader.py). adaugat `capture_live(on_arp=...)` + `read_pcap_arp()`,
paralel cu fluxul IP existent, neatins. detectia: urmareste legaturile
IP<->MAC afirmate de trafic ARP in ordine cronologica, flagheaza cand
aceeasi adresa e revendicata de un MAC diferit. limitare asumata:
schimbari legitime de MAC (placa noua, VM migrat, DHCP) sunt fals-pozitive
posibile, la fel ca orice semnatura comportamentala.

**DNS tunneling** (`nids/capture/dns_meta.py` + `nids/signatures/dns_tunneling.py`)
- DNS (spre deosebire de HTTPS) circula necriptat, deci poate fi inspectat
real. euristica clasica: entropie Shannon mare + lungime mare pe eticheta
de subdomeniu (text ales de oameni are entropie joasa, date encodate
base32/64/hex se apropie de 4+ biti/caracter). praguri implicite (30
caractere, 3.5 biti/caracter) validate empiric cu stringuri reale (hash
hex ~3.8, base64 ~4.6, text normal ~0). a doua cale de captura noua
(`on_dns`, subset al pachetelor IP - DNS ruleaza peste UDP).

**semnaturi malware in payload** (`nids/capture/payload_meta.py` +
`nids/signatures/payload_signatures.py`) - a treia cale de captura noua
(`on_payload`). set mic, curatat manual, de pattern-uri cunoscute (EICAR
- semnatura STANDARD de test antivirus, traversare de director, SQL
injection, XSS, marker de webshell) - potrivire simpla de subsir de
octeti, nu regex/motor de reguli complet. **payload-ul NU e stocat
nicaieri pe termen lung** (spre deosebire de PacketMeta) - trecut o
singura data prin callback pentru scanare, apoi aruncat, exact ca sa evite
cresterea de memorie deja documentata ca risc la volum mare de trafic.
LIMITARE REALA, documentata explicit si in UI (nu doar in cod): functioneaza
DOAR pe trafic necriptat - HTTPS/TLS (majoritatea traficului modern)
ramane opac, la fel ca oricarui NIDS bazat pe retea, nu doar acestuia.
checkbox de activare/dezactivare in SignaturesPanel (implicit activat).

toate patru: `detect_X()` (batch, PCAP) + `XTracker` (live streaming),
acelasi tipar consistent folosit deja pentru port_scan/sensitive_ports.
wired complet in analyze_pcap/analyze_pcap_hybrid + DashboardPanel
(live) + SignaturesPanel (UI). 407 teste in total dupa acest lot.

## honeypot (prima din cele trei "extinderi viitoare" - user a ales sa incepem cu asta)

CONTEXT-nids.md mentiona honeypot/packet forensics/scanner de vulnerabilitati
ca extensii viitoare ale acestui proiect, nu proiecte separate. userul a
ales sa inceapa cu honeypot-ul - cel mai aliniat cu ce exista deja (Loguri,
Raspuns), si singurul semnal din toata aplicatia FARA risc de fals-pozitiv:
niciun serviciu legitim nu asculta pe un port de honeypot, deci orice
conexiune acolo e prin definitie suspecta.

- **modul nou `nids/honeypot/`** (nu `signatures/` - nu e detectie pasiva
  peste pachete capturate, e un serviciu ACTIV care asculta):
  - `listener.py::run_honeypot()` - un singur thread, `selectors`
    (neblocant) peste toate porturile configurate simultan, plus un
    thread SCURT separat per conexiune acceptata (trimite un banner
    minim daca exista unul pentru acel port, citeste cel mult 256 octeti
    cu timeout 2s, inchide) - o conexiune lenta nu blocheaza acceptarea
    altora. eroare de bind pe un port (deja ocupat, sau interzis de OS -
    vezi mai jos) nu opreste restul porturilor, doar raporteaza si
    continua cu ce a reusit
  - **niciun protocol real emulat** - doar un banner static (SSH/Telnet)
    si logare a ce trimite clientul, NICIODATA interpretat/executat. fara
    asta ar deveni el insusi o suprafata de atac, exact ce nu trebuie
    sa fie un honeypot safe
  - porturi implicite mari (2222, 8080, 3306 - nu 22/23/445/3389 direct,
    ca sa nu intre in conflict cu servicii reale care ar putea rula deja
    pe alea, si ca sa nu ceara drepturi de administrator (>1024))
- `HoneypotThread` (QThread) - acelasi tipar ca LiveCaptureThread/
  SimulationThread (subclasare directa, run() = un singur apel blocant)
- `HoneypotPanel` - self-continut (spre deosebire de SignaturesPanel/
  MlSettings/ResponseSettings, nu are nevoie sa fie citit de alt panou -
  doar scrie in EventStore, la fel ca orice alta sursa). camp de porturi
  editabil + buton pornit/oprit, ca la simulare. **bug prins in timpul
  scrierii testelor**: daca toate porturile esueaza la bind, thread-ul
  se termina aproape imediat, iar handler-ul generic de "thread terminat"
  suprascria mesajul de eroare cu "honeypot oprit" inainte sa apuce
  userul sa-l vada - fixat cu un flag `_had_bind_error` care pastreaza
  mesajul relevant
- **bug de mediu prins la testare, nu de cod**: un test cu porturi fixe
  (58233/58234) esua constant cu timeout la conectare - investigat pana
  la cauza reala: acel port specific era interzis la bind pe Windows
  (`PermissionError: WinError 10013`), probabil o rezervare Hyper-V/WSL
  care nu apare in `netsh interface ipv4 show excludedportrange`. fix:
  toate testele descopera un port liber dinamic (bind pe portul 0, apoi
  `getsockname()`) in loc sa presupuna numere fixe - robust indiferent
  de ce rezervari de porturi are masina curenta
- honeypot-ul salveaza direct in EventStore (ca orice sursa) - apare
  automat in Loguri, nu in lista live din Dashboard (care e legata strict
  de o sesiune de monitorizare/PCAP) - scop deliberat mai restrans, sa nu
  cupleze HoneypotPanel de DashboardPanel fara motiv
- **neimplementat inca, notat ca pas urmator posibil**: ideea din
  CONTEXT-nids.md ca honeypot-ul sa devina sursa de date reale pentru
  reantrenarea modelului expert (in loc de doar NSL-KDD static) - scop
  separat, mult mai mare, nu a fost cerut inca

## raspuns automat (nivelul din CONTEXT-nids.md ramas neimplementat)

CONTEXT-nids.md prevedea de la inceput doua niveluri de raspuns: "automat,
dar strict safe/reversibil" SI "manual, human-in-the-loop" - doar cel
manual fusese construit. user a observat lipsa si a cerut explicit optiunea.

decizii (confirmate cu userul, nu presupuse):
- prag FIX: doar BOTH_ATTACK (ambele modele de acord) - cel mai increzator
  caz, indiferent de strict_reporting (BOTH_ATTACK trece oricum de acel
  filtru, deci nu exista interactiune ciudata intre cele doua setari)
- DOAR evenimente ML - semnaturile (port scan, porturi sensibile) raman
  strict manuale, au o rata de fals-pozitiv cunoscuta si diferita
- dezactivat implicit (opt-in) - blocarea, chiar temporara/reversibila,
  e o actiune reala, nu ceva ce ar trebui sa surprinda userul din prima
  pornire

implementare:
- `nids/core/response_settings.py` (nou) - `ResponseSettings`, acelasi
  tipar ca `MlSettings` (dataclass simplu, nu widget, creat o data in
  MainWindow, dat la DashboardPanel si ResponsePanel) - dar SPRE DEOSEBIRE
  de MlSettings, citit LIVE la fiecare tick ML, nu doar la pornirea
  monitorizarii - poti porni/opri din Raspuns in mijlocul unei sesiuni
  active, fara sa fie nevoie de restart
- `ml_combination.BOTH_ATTACK_EVENT_TYPE` - constanta publica (event_type-ul
  exact folosit de describe_agreement() pentru BOTH_ATTACK), ca
  DashboardPanel sa aiba un criteriu stabil de verificat fara sa
  duplice logica de combinare sau sa lege Event de enum-ul Agreement
- `DashboardPanel._maybe_auto_block()` - apelata din `_on_ml_evaluation_tick()`
  pentru fiecare eveniment nou. verifica in ordine: setarea e activa? e
  BOTH_ATTACK? IP-ul e deja blocat? (idempotenta - evita sa umple Loguri
  cu acelasi "blocare automata" la fiecare conexiune noua de la un IP deja
  blocat). apoi block_manager.block(), cu acelasi tratament de
  BlockRuleError ca la blocarea manuala (mesaj clar, "blocare automata
  esuata" in Loguri, nu crash) - reutilizeaza tot ce a fost construit
  pentru bug-ul de blocare fara drepturi de Administrator
  - evenimentul "blocare automata" mosteneste dest_ip/porturi/protocol/
    assessment_json de la evenimentul ML original - analizabil din Loguri,
    la fel ca "blocare manuala"
- `ResponsePanel` are acum un checkbox "blocare automata" langa tabelul
  de blocari active, legat direct de ResponseSettings

## limita de afisare din Loguri: 200 -> 2000

user a intrebat daca n-ar trebui sa "tinem minte" mai mult in Loguri
(comparativ cu limita de 500 din Trafic). clarificare importanta: DB-ul
(data/nids.db) NU sterge NICIODATA nimic - "limita" era doar cate randuri
se AFISEAZA (EventStore.recent()/events_for_source(), query SQL cu
LIMIT), nu ce se pastreaza. la fel la Trafic - `_all_packets` (folosit
pentru reanaliza ML) creste nelimitat, doar tabelul VIZIBIL e capat la
500 pentru performanta randare.

de ce nu literalmente "toate": LogsPanel reconstruieste tot tabelul din
SQLite la fiecare 2 secunde (interogare noua + toate celulele recreate) -
la un numar nelimitat, dupa saptamani de utilizare cu multe evenimente,
reconstructia asta ar putea incepe sa incetineasca UI-ul vizibil.

fix: `EventStore.DEFAULT_DISPLAY_LIMIT` (nou, 2000, inlocuieste 200-ul
hardcodat din semnaturile `recent()`/`events_for_source()`) - generos
pentru utilizare normala, fara riscul de incetinire al lui "fara limita".
export-ul HTML ramane la 10 000 (deja seta explicit acest limit, neafectat).

## modelul local, faza 2: scor continuu + hyperparametri + investigatie stabilitate

user a observat 89 de evenimente in 5 minute (toate "doar model local") si
a cerut explicit sa facem modelul local "mai complex". trei imbunatatiri,
in ordinea ceruta:

1. **scor continuu de anomalie** (nu doar binarul anomalie/normal):
   - `LocalModel.anomaly_score()` - inversul lui `decision_function()` din
     sklearn (conventie proprie: mai mare = mai anormal, spre deosebire de
     sklearn unde negativ = anomalie)
   - `LocalModelManager.anomaly_score()` - la fel ca `predict_only()`,
     None cat timp modelul e in modul invatare
   - `ml_combination.severity_from_local_score()` - 3 praguri euristice
     (usor/moderat/sever la 0.05/0.15) - NU calibrate statistic (Isolation
     Forest n-are o scala universala intre seturi de date), doar o
     impartire rezonabila. `event_for_agreement()` foloseste asta pentru
     BOTH_ATTACK/LOCAL_ONLY (singurele cazuri unde modelul local a
     confirmat un semnal) - inainte, orice flag local era mereu HIGH,
     acum severitatea reflecta cat de departe e conexiunea de "normal"
   - `ConnectionAssessment.local_anomaly_score` + afisat in
     ConnectionInspectorDialog ("scor anomalie: +0.180, sever")
   - inclus in assessment_json (backward compatibil - `.get()` cu default
     None pentru evenimente vechi, salvate inainte de acest camp)

2. **n_estimators configurabil** (numarul de arbori Isolation Forest) -
   nou camp `MlSettings.n_estimators`, implicit 100 (exact valoarea
   implicita sklearn - niciun comportament schimbat pana nu il ajusteaza
   userul manual). plumbing: LocalModel.train() -> LocalModelManager
   (stocat, folosit la fiecare _retrain()) -> UI. NU am schimbat
   `max_samples` (ramane 'auto' = min(256, n)) - e deja practica
   recomandata din lucrarea originala Isolation Forest, fara un motiv
   concret sa se abata de la ea

3. **investigatie stabilitate feature-uri de trafic** - concluzie: NU e
   un bug de cod. `extract_nsl_kdd_style_features()` creeaza un
   `TrafficWindowTracker()` nou la fiecare tick (5s) si reproceseaza TOATE
   pachetele sesiunii in ordine cronologica - fereastra e recalculata
   corect si consistent "ca acum", nu e stale/instabila intre tick-uri.

   motivul REAL al zgomotului: o conexiune e evaluata O SINGURA DATA, la
   tick-ul unde apare prima oara ca "noua" - daca la momentul respectiv
   conexiunea abia a inceput (doar 1-2 pachete vazute), `duration≈0`,
   `src_bytes` minim, `flag="S0"` (fara raspuns inca) - vezi
   nids/ml/features/connection.py::_build_connection(). traficul de
   simulare (butonul "Simuleaza port scan") genereaza EXACT acest profil
   (conexiuni TCP scurte, adesea fara raspuns) - structural identic cu ce
   ar arata un SYN flood real (neptune in NSL-KDD). deci modelul local
   flagheaza CORECT ceva structural diferit de traficul normal complet
   (SF, durata reala, octeti reali) - nu e o eroare de calcul, e
   comportamentul asteptat al unui detector de anomalii pe trafic
   deliberat anormal (chiar daca "safe"). nicio schimbare de cod aici -
   parghiile reale raman cele din faza 1 (strict mode, contamination)

## panoul ML a devenit configurabil (userul a cerut explicit "mai complex, mai customizable")

focusul e pe modelul local - cel expert e deja pre-antrenat static, nimic
de ajustat live acolo. patru categorii de setari, toate citite din nou
DOAR la urmatoarea pornire a monitorizarii (la fel ca pragul de port scan
din SignaturesPanel) - nu se aplica instant in mijlocul unei sesiuni deja
pornite.

- **nids/core/ml_settings.py** (nou) - `MlSettings`, un dataclass simplu
  (nu un widget), impartit intre MlPanel (il modifica) si DashboardPanel
  (il citeste la start). motivul pentru care nu e direct pe MlPanel:
  MlPanel are nevoie de DashboardPanel pentru starea live (polling), iar
  DashboardPanel are nevoie de setarile din MlPanel la start - o
  dependinta circulara directa intre widget-uri. `MlSettings()` e creat
  o singura data in MainWindow, dat la ambele
- **antrenare model local**: min_training_samples (prag cold-start),
  retrain_every, max_buffer_size (fereastra glisanta) - deja existau ca
  parametri de constructor pe LocalModelManager, doar nu erau expuse in UI
- **sensibilitate (contamination)**: parametru nativ Isolation Forest -
  rata asteptata de anomalii, controleaza direct cat de usor marcheaza
  ceva ca anomalie. adaugat prin tot lantul: LocalModel.train() ->
  LocalModelManager (stocat, folosit la fiecare _retrain()) -> UI. checkbox
  "automat" (implicit, pastreaza comportamentul vechi = sklearn
  `contamination='auto'`) + spinbox manual (0.01-0.5) cand e debifat
- **strictete raportare**: `event_for_agreement()` are acum parametrul
  `strict` - daca e True, suprima orice eveniment in care NU sunt de
  acord ambele modele (EXPERT_ONLY, LOCAL_ONLY, LOCAL_LEARNING+expert
  flag), pastreaza doar BOTH_ATTACK. implicit False = comportamentul
  vechi (orice semnal, chiar de la un singur model, genereaza eveniment).
  `LiveHybridAnalyzer` primeste `strict_reporting` la constructor si il
  paseaza mai departe - local_manager.process() tot ruleaza normal
  (modelul local invata oricum), doar decizia de RAPORTARE se schimba
- **cadenta evaluare live**: fostul `_ML_EVALUATION_INTERVAL_MS` (constanta
  fixa, 5000ms) a devenit `MlSettings.evaluation_interval_ms`, citit de
  `_ml_timer.start(...)` la fiecare pornire. panoul il arata in secunde
  (UX), il converteste intern in ms

## Semnaturi mai complexe + istoric de blocari (cele doua idei ramase deschise de mult)

celelalte doua idei oferite mai demult si neconfirmate atunci - prag de
timp pentru port scan si porturi sensibile - au fost confirmate acum,
implementate impreuna cu un istoric de blocari in Raspuns.

- **fereastra de timp pentru port scan** - implicit `None` (comportamentul
  original, cumulativ pe toata sesiunea/tot fisierul), optional un interval
  in secunde: cele N porturi trebuie atinse INAUNTRUL ferestrei, nu oricand
  in sesiune - mai aproape de o scanare reala (rafala scurta)
  - `nids/signatures/port_scan.py::detect_port_scans()` (PCAP/batch) -
    `_ports_within_first_window_reaching_threshold()`: fereastra glisanta
    peste hit-urile (port, timestamp) unei perechi, in ordine cronologica
  - `nids/core/analysis.py::StreamAnalyzer` (live) - acelasi principiu, dar
    incremental: la fiecare pachet, elimina hit-urile mai vechi decat
    `timestamp - window_seconds` din lista pastrata pentru acea pereche,
    apoi verifica pragul pe ce a ramas. un port re-contactat DUPA ce a
    iesit din fereastra conteaza din nou ca "nou" (semnal proaspat, nu
    istoric)
- **semnatura noua: porturi sensibile** (`nids/signatures/sensitive_ports.py`)
  - rezolva golul semnalat explicit de user: un atacator care tinteste
    doar 1-2 porturi critice (SSH/RDP/SMB), sub pragul de port scan, ar
    trece complet neobservat de semnatura veche
  - semnaleaza la PRIMUL contact, fara niciun prag - un singur pachet
    catre un port din lista e destul. severitate HIGH (mai mare decat
    port scan-ul, MEDIUM) - un contact neasteptat catre un port critic
    e considerat un semnal mai puternic decat "atatea porturi distincte"
  - `detect_sensitive_port_contacts()` (batch/PCAP) + `SensitivePortTracker`
    (live, dedup per sesiune pe (sursa, destinatie, port))
  - evenimentul salveaza dest_ip/dest_port (identitate de conexiune) -
    beneficiu secundar: poate fi analizat si din Loguri daca pachetele
    conexiunii mai sunt in sesiunea curenta, la fel ca evenimentele ML
- **SignaturesPanel**: lista de porturi sensibile e EDITABILA din UI (cerut
  explicit de user, nu hardcodata) - camp text cu porturi separate prin
  virgula, parsat live, ignora tacut token-uri invalide; implicit 22
  (SSH), 23 (Telnet), 445 (SMB), 3389 (RDP). fereastra de timp: checkbox
  "fara limita" (implicit bifat = comportamentul vechi) + spinbox secunde
- **istoric de blocari in Raspuns** (`BlockManager.history()`) - inainte,
  o blocare care expira disparea complet din tabel, fara nicio urma ca
  s-a intamplat ceva (user a semnalat asta ca neclar). fiecare blocare
  primeste acum o `BlockHistoryEntry` care supravietuieste blocarii
  active corespunzatoare - `unblocked_at`/`ended_by` ("manual" / "expirat"
  / "oprire aplicatie") raman None cat timp blocarea e activa. NU e
  persistat pe disc (se reseteaza la fiecare pornire a aplicatiei, ca
  intreaga stare BlockManager) - istoricul PERMANENT tot ramane in Loguri
  (evenimentul "blocare manuala" salvat separat la block-time)
  - ResponsePanel are acum un al doilea tabel sub cel de blocari active,
    cele mai recente intai

## honeypot -> reantrenare model expert (a doua idee ramasa deschisa, dupa ce roadmap-ul de baza s-a incheiat)

CONTEXT-nids.md (versiunea mai veche, ramificata) mentiona ideea ca honeypot-ul
sa devina sursa de date reale pentru reantrenarea modelului expert, in loc de
doar NSL-KDD static - notat ca "neimplementat inca" in sectiunea honeypot de
mai sus. userul a cerut acum sa o construim.

problema de rezolvat: honeypot-ul (`nids/honeypot/listener.py`) e un socket
de ascultare simplu - stie doar src_ip/porturi/preview text, nu are acces la
pachetele brute de retea si deci nu poate produce direct cele 28 de features
NSL-KDD-style asteptate de model.

solutie, cu reutilizare maxima a pipeline-ului existent, in loc de un
extractor de features separat doar pentru honeypot:

- **`HoneypotHit`** (nids/honeypot/listener.py) are acum si `bytes_received`
  si `duration` (ambele cu default, backward compatibil) - masurate in
  `_handle_connection()` cu `time.monotonic()` in jurul citirii socketului
- **`nids/honeypot/training_data.py`** (nou) - `hit_to_packets()` reconstruieste
  o interactiune honeypot ca o secventa MICA de `PacketMeta` sintetice (SYN,
  SYN-ACK, eventual un pachet cu datele primite, FIN) - NU pachete reale, doar
  suficient de plauzibile ca `extract_nsl_kdd_style_features()` (ACELASI
  extractor folosit pentru trafic real capturat) sa produca un record complet
  cu toate cele 28 de features, fara cod nou de extragere. toate interactiunile
  folosesc un `dst_ip` placeholder comun (`HONEYPOT_HOST_IP`) - corect
  semantic, honeypot-ul chiar RULEAZA pe o singura masina, deci statisticile
  per-destinatie din TrafficWindowTracker reflecta realitatea (multi atacatori,
  aceeasi "gazda")
  - `HoneypotTrainingStore` - acumuleaza sesiunile (liste de pachete) pe disc
    intre pornirile aplicatiei, la fel ca LocalModelManager - fara asta ar
    trebui sa lasi honeypot-ul sa colecteze ore intregi intr-o singura rulare
- **`nids/ml/expert/retrain.py`** (nou) - `retrain_with_honeypot_data()`:
  incarca NSL-KDD normal, antreneaza un RandomForest BASELINE (ca sa masuram
  acuratetea "inainte"), apoi adauga peste `x_train` conexiunile honeypot
  (encodate cu `encode_features()`, aliniate pe coloanele din train) -
  etichetate INTOTDEAUNA "atac" (label=1), fara exceptie, spre deosebire de
  restul aplicatiei unde exista mereu risc de fals-pozitiv - antreneaza un
  al doilea RandomForest pe setul combinat, evalueaza tot pe KDDTest+ (acelasi
  test set, comparatie corecta), face un backup `.bak` al modelului anterior
  INAINTE sa suprascrie `data/models/expert_random_forest.joblib` - reantrenarea
  trebuie sa fie la fel de reversibila ca o blocare de IP, nu o operatie
  definitiva pe modelul deja validat
- **`RetrainThread`** (nids/ui/retrain_thread.py) - subclasare QThread directa,
  acelasi tipar ca toate celelalte thread-uri din proiect - antrenarea a DOUA
  RandomForest-uri poate dura cateva secunde, nu trebuie sa inghete UI-ul
- **HoneypotPanel**: buton nou "Reantreneaza modelul expert cu date honeypot",
  activat doar peste `MIN_HONEYPOT_SAMPLES` (10, prag arbitrar, ca la modelul
  local) conexiuni acumulate, cu `QMessageBox.question()` de confirmare
  explicita inainte (actiune care schimba modelul activ, nu ceva de facut din
  greseala la un click), si status cu acuratetea inainte/dupa dupa terminare
- **capcana prinsa la scriere, inainte sa ajunga bug real**: `finished` (semnalul
  automat QThread) se emite DUPA `succeeded`/`failed` - handler-ul generic de
  "thread terminat" nu trebuie sa mai apeleze acelasi cod care seteaza textul
  de status, altfel suprascrie mesajul cu acuratetea rezultata cu un text
  generic - exact tiparul de bug deja gasit o data la honeypot cu
  `_had_bind_error` (vezi BUGS.md), de data asta prins inainte sa ajunga bug
  vizibil pentru user

teste noi: test_honeypot_training_data.py (hit_to_packets, persistenta
HoneypotTrainingStore), test_expert_retrain.py (retrain_with_honeypot_data,
cu un NSL-KDD "jucarie" scris in tmp_path, nu setul real de 150k randuri -
acelasi principiu ca testele existente pe nsl_kdd.py), teste noi in
test_honeypot_panel.py (prag, confirmare, RetrainThread inlocuit cu un fals
in testele de UI - antrenarea reala nu trebuie sa ruleze intr-un test de widget).

## packet forensics / analizator de trafic avansat (a treia idee ramasa deschisa)

a treia idee mentionata in CONTEXT-nids.md (versiunea ramificata) ca extensie
viitoare - o vedere mai adanca decat "Trafic" (metadate) sau analiza ML
(features agregate): fluxul BRUT, pachet cu pachet, al unei conexiuni, plus
inspectia continutului efectiv (hex dump) cand exista.

doua capabilitati noi, ambele in `nids/ui/widgets/forensics_panel.py`:

- **"Reconstruieste conexiunea completa"** - a doua optiune in meniul
  contextual din Trafic (langa "Analizeaza aceasta conexiune cu ML").
  `packets_for_connection()` (functie pura, usor de testat) filtreaza
  `_all_packets` (deja pastrat pentru sesiunea curenta) dupa perechea de
  capete + protocol, in ambele directii, sortat cronologic -
  `ConnectionTimelineDialog` arata timpul relativ (+0.000s, +0.015s...),
  directia (-> / <-), flag-urile TCP si dimensiunea fiecarui pachet. spre
  deosebire de analiza ML (features agregate: duration/src_bytes/flag unic),
  aici vezi exact SECVENTA de pachete - util sa intelegi "ce s-a intamplat
  de fapt" intr-un schimb (ex: cate retransmisii, unde a picat conexiunea)
- **hex dump pe payload** - `PayloadSample` (nids/capture/payload_meta.py)
  contine deja octetii bruti (`payload: bytes`), captati pentru scanarea de
  semnaturi malware, dar niciodata afisati userului pana acum. panoul nou
  **Forensics** (dock nou, tabifiat cu Loguri/Trafic) le colecteaza intr-o
  fereastra glisanta IN MEMORIE (`deque(maxlen=200)`) - NU persistate pe
  disc, aceeasi decizie ca la semnaturile de payload (NOTES.md, sectiunea
  "patru semnaturi noi"). dublu-click pe un rand deschide `HexDumpDialog`
  (non-modal, ca ConnectionInspectorDialog) cu `hex_dump()` - format clasic
  offset/hex/ascii, functie pura fara dependinte noi
- DashboardPanel primeste `forensics_panel` ca parametru OPTIONAL (implicit
  None) - la fel ca `ml_settings`/`response_settings` - ca sa nu strice
  semnatura constructorului pentru toate testele existente care il
  instantiaza direct fara acest panou
- payload-urile ajung in Forensics din DOUA surse, ca sa functioneze si la
  PCAP static si la monitorizare live: `_on_live_payload_sample()` (acelasi
  loc unde ajunge deja la `PayloadSignatureTracker`) si `_on_load_clicked()`
  (apel separat `read_pcap_payload_samples(path)`, in plus fata de
  `analyze_pcap`/`analyze_pcap_hybrid` care il citesc oricum intern pentru
  semnaturi - acelasi tipar deja existent, `_all_packets = read_pcap(path)`
  re-citeste si el fisierul separat de `analyze_pcap`)

teste noi: test_forensics_panel.py (hex_dump, packets_for_connection,
ForensicsPanel, ConnectionTimelineDialog - constructie fara `.show()`/`.exec()`
real, la fel ca la ConnectionInspectorDialog), test_dashboard_forensics.py
(cablarea in DashboardPanel), plus teste noi in test_traffic_panel.py pentru
semnalul `reconstruct_requested`. 442 teste in total dupa acest lot.

## scanner de vulnerabilitati (a patra si ultima idee din lista ramasa deschisa)

diferit de restul aplicatiei: pana acum totul e detectie PASIVA (analizeaza
trafic care exista deja). un scanner de porturi/vulnerabilitati e prima
componenta ACTIVA - initiaza el insusi conexiuni catre alte masini, ca sa
descopere ce servicii asculta. decizii de scop, luate explicit ca sa ramana
un instrument defensiv/de audit propriu, nu ceva ce ar putea fi confundat
cu un tool de recunoastere:

- **STRICT limitat la reteaua privata proprie** - `is_scannable_target()`
  (nids/scanner/vulnerability_scan.py) foloseste `ipaddress.ip_address(host).is_private`
  - orice adresa publica e refuzata cu `ValueError`, atat in `scan_host()`
  cat si in `scan_targets()` (care valideaza TOATE tintele INAINTE sa
  inceapa scanarea, nu doar sare peste cele gresite - un singur IP public
  intr-o lista respinge tot apelul). acelasi principiu ca `nids/core/simulation.py`,
  care tinteste explicit doar propriul IP din reteaua locala
- **tinte explicite, introduse de user** - NU descoperire automata a
  intregii retele (nu se face ping sweep pe un /24 intreg) - human-in-the-loop,
  la fel ca blocarea manuala de IP, nu un "network mapper" automat
- **scanare TCP connect simpla** (`connect_ex()`, conexiune completa) - NU
  SYN stealth scan sau alte tehnici de evaziune, nimic ascuns. aceeasi
  tehnica de baza ca `Test-NetConnection`/telnet
- **note de risc STATICE, per protocol** (`_KNOWN_RISKS` - dict port ->
  text), NU o baza de date de CVE-uri reala - ar cere o sursa externa/API
  de internet plus potrivire exacta de versiune de software, greu de facut
  corect fara o sursa de date live intretinuta constant. scop: semnaleaza
  "acest tip de serviciu are riscuri cunoscute daca e expus" (SMB/RDP/
  Telnet/FTP/VNC/etc.), nu un raport de securitate complet
- banner grab REFOLOSESTE aceeasi conexiune care a confirmat ca portul e
  deschis, nu deschide una noua separat - **bug prins la scrierea testelor,
  nu presupus**: o a doua conexiune separata poate ajunge intercalata/
  refuzata de un server cu backlog mic, banner-ul se pierdea in mod
  nedeterminist (vezi BUGS.md)
- rezultatele se salveaza in EventStore ca orice alta sursa (`event_type
  = "scanare vulnerabilitati"`) - severitate MEDIUM daca portul are un risc
  cunoscut, LOW altfel - vizibile si cautabile din Loguri ca orice eveniment

`ScannerPanel` (nou, self-continut, acelasi tipar ca HoneypotPanel) + `ScanThread`
(QThread, acelasi tipar ca toate celelalte thread-uri din proiect). dock nou
"Scanner", tabifiat cu Semnaturi/ML/Raspuns/Honeypot. `ScannerPanel.stop()`
asteapta sincron thread-ul la inchiderea aplicatiei - proactiv, nu dupa ce
un user ar fi gasit bug-ul: acelasi tipar de cursa ca la LogsPanel (salvare
intr-un EventStore deja inchis), evitat de data asta INAINTE sa ajunga bug
vizibil.

teste noi: test_vulnerability_scan.py (is_scannable_target, scan_host cu un
server real pe 127.0.0.1 si port liber descoperit dinamic, scan_targets,
event_from_scan_result), test_scanner_panel.py (parsare tinte, ScanThread
inlocuit cu un fals in testele de UI, la fel ca la honeypot/reantrenare).
459 teste in total dupa acest lot - toate cele 4 idei ramase din roadmap-ul
extins (honeypot -> reantrenare, packet forensics, scanner de vulnerabilitati)
sunt acum implementate.

## fereastra glisanta a modelului local: 2000 -> 10000 conexiuni

user a observat 60000+ PACHETE in doar 2 ore de monitorizare live si s-a
intrebat daca bufferul modelului local (MAX_BUFFER_SIZE) n-ar trebui marit.
clarificare importanta: bufferul tine CONEXIUNI agregate (NslKddStyleFeatures),
nu pachete brute - numarul real de conexiuni e mult mai mic decat 60000, dar
tot suficient cat sa "recicleze" o fereastra de 2000 destul de repede pe
sesiuni lungi cu trafic de volum mare.

verificat explicit ca cele doua praguri sunt independente: MIN_TRAINING_SAMPLES
(cold start, 50) controleaza CAND incep predictiile, MAX_BUFFER_SIZE doar CAT
de multa istorie se pastreaza dupa - marirea bufferului nu intarzie deloc
inceperea predictiilor.

cost de antrenare neschimbat practic: Isolation Forest foloseste
`max_samples='auto'` = min(256, n) per arbore - indiferent de marimea
bufferului, fiecare arbore vede tot un subesantion de 256. singurul cost
real al unui buffer mai mare e adaptare mai lenta la schimbari legitime de
trafic (concept drift) - deja o limitare cunoscuta si acceptata a
proiectului, nu un risc nou introdus.

`MAX_BUFFER_SIZE` (nids/ml/local/learning.py) ridicat de la 2000 la 10000 -
era deja reglabil din panoul ML (interval 50-20000), dar `MlSettings()` nu
se persista intre restart-uri ale aplicatiei, deci merita schimbata si
valoarea implicita din cod, nu doar cea din UI.

## strict_reporting implicit True (dupa testare reala cu scanner-ul de vulnerabilitati)

user a testat scanner-ul de vulnerabilitati impotriva propriului router
(192.168.1.1) si a observat Loguri umplandu-se cu multe randuri "atac (ambele
modele de acord)" identice, plus alte semnaturi (port scan de la adrese
externe reale). a cerut ca panoul ML sa porneasca implicit cu "raporteaza
doar cand ambele modele sunt de acord" bifat (checkbox deja existent, doar
neactivat implicit).

clarificare facuta inainte de schimbare: NU e vorba de blocarea automata
(ResponseSettings.auto_block_enabled, ramane opt-in - ar fi fost periculos
sa se activeze implicit, ar fi blocat automat routerul userului chiar in
testul din care a venit cererea). e vorba strict de FILTRAREA a ce se
AFISEAZA in Loguri, `MlSettings.strict_reporting` - nicio actiune asupra
retelei.

schimbare: `MlSettings.strict_reporting` implicit `False` -> `True` -
motivat de zgomotul real observat (multe flag-uri de la un singur model,
care ingreuneaza gasirea semnalelor de incredere mare). `event_for_agreement()`
cu strict=True raporteaza DOAR BOTH_ATTACK, restul (EXPERT_ONLY, LOCAL_ONLY,
LOCAL_LEARNING+expert) sunt suprimate din Loguri (modelul local tot invata
normal in fundal, doar decizia de RAPORTARE se schimba).

test actualizat: `test_start_monitoring_with_default_settings_matches_previous_behavior`
redenumit in `..._matches_current_defaults`, asertiunea schimbata din
`is False` in `is True`. `test_ml_tick_adds_event_to_dashboard`
(test_dashboard_live_ml.py) testeaza explicit scenariul PERMISIV (expert
singur semnaleaza) - are acum nevoie de `MlSettings(strict_reporting=False)`
explicit trimis la panel, altfel evenimentul testat ar fi suprimat de noul
default si testul nu ar mai verifica ce trebuie.

## observatie confirmata prin testare: scanner-ul de vulnerabilitati e vazut ca atac de ML - asteptat, nu bug

user a scanat propriul router (192.168.1.1) cu noul scanner de vulnerabilitati
si a observat ca traficul GENERAT DE SCANNER a fost flagat "atac (ambele
modele de acord)" de mai multe ori.

nu e un bug: scanner-ul face exact ce arata structural ca un port scan/atac -
multe conexiuni TCP scurte, catre porturi diferite, aceeasi destinatie, intr-
un interval scurt (`duration≈0`, `flag="S0"` pentru porturile ce nu raspund).
identic structural cu problema deja investigata la "modelul local, faza 2"
pentru butonul de simulare - un detector de anomalii pe trafic deliberat
"anormal" (scanare) il recunoaste CORECT ca fiind diferit de trafic normal,
chiar daca intentia din spate e benigna.

de ce apare de mai multe ori identic: fiecare port scanat e o conexiune
(tuplu 5 valori) DISTINCTA, evaluata separat de LiveHybridAnalyzer (dedup pe
identitatea completa a conexiunii, nu doar sursa/destinatie) - daca mai multe
porturi din scanare arata individual "suspect" structural, fiecare genereaza
propriul eveniment. confirma, de fapt, ca aplicatia ar prinde un scanner real
daca ar rula impotriva retelei userului.

## poarta de siguranta la reantrenarea din honeypot: nu suprascrie modelul activ daca acuratetea scade

user a intrebat un lucru important dupa prima testare reala a reantrenarii:
datele honeypot chiar ajuta modelul expert, sau l-ar putea strica? raspuns
onest: da, exista un risc real, si codul initial NU se apara de el.

doua probleme identificate:
1. pachetele sintetice generate din honeypot (`hit_to_packets()`) sunt
   structural foarte OMOGENE - mereu `flag="SF"`, mereu `protocol="tcp"`,
   `service` aproape mereu "other" (porturile honeypot 2222/8080 nu sunt in
   tabelul de servicii cunoscute) - mult mai putin diverse decat atacurile
   reale din NSL-KDD. un lot de exemple prea asemanatoare intre ele ar putea
   ingusta ce a invatat modelul, nu doar sa il extinda
2. **codul reantrena mereu de la zero pe NSL-KDD + honeypot si SALVA noul
   model indiferent daca acuratetea pe KDDTest+ scadea fata de modelul
   ACTIV curent** - arata cifrele in UI, dar nu opreau nimic. backup-ul .bak
   exista, dar restaurarea era manuala - userul ar fi trebuit sa observe
   singur regresia

fix (`nids/ml/expert/retrain.py`):
- `accuracy_before` acum se calculeaza evaluand MODELUL ACTIV CHIAR SALVAT
  pe disc (`ExpertModel.load(model_out_path)`), NU un baseline nou-antrenat
  doar din NSL-KDD ca inainte - comparatia corecta e cu ce ruleaza chiar
  acum, care ar putea deja contine imbunatatiri dintr-o reantrenare
  anterioara. beneficiu secundar: cand exista deja un model, nu se mai
  antreneaza un RandomForest suplimentar doar pentru comparatie - un fit()
  mai putin fata de varianta initiala
- `_is_at_least_as_good(accuracy_before, accuracy_after)` - functie pura,
  usor de testat fara ML real - daca noul model iese mai slab, `model_saved
  = False` si NU se atinge deloc fisierul de pe disc (nici macar backup,
  nu era nimic de suprascris)
- cazul "niciun model activ inca" (prima reantrenare vreodata) ramane
  neconditionat - nimic de "stricat", se salveaza mereu; se antreneaza
  totusi un baseline NSL-KDD doar ca sa existe o cifra informativa in mesaj
- `RetrainResult` are acum campul `model_saved: bool` - `HoneypotPanel`
  arata un mesaj diferit cand reantrenarea NU a imbunatatit acuratetea
  ("modelul activ NU a fost schimbat"), fara sa lase impresia gresita ca
  s-a intamplat ceva

teste noi: `_is_at_least_as_good` (3 teste, fara ML real), scenariile
"fara model anterior -> salveaza mereu", "cu model anterior + imbunatatire
-> salveaza si face backup", "cu model anterior + regresie -> NU salveaza,
fisierul original ramane neschimbat byte-cu-byte" (ultimele doua forteaza
rezultatul comparatiei prin monkeypatch pe `_is_at_least_as_good`, ca sa nu
depinda de cum iese antrenarea reala pe date jucarie minuscule). fixture-ul
"model anterior" a trecut de la octeti fictivi la un ExpertModel REAL salvat
- codul acum chiar il incarca (`ExpertModel.load()`) ca sa il evalueze, nu
doar ii verifica existenta fisierului.

## note tehnice minore

- `python -m nids.ui.main` porneste un proces PARINTE care, la randul
  lui, porneste un proces COPIL cu aceeasi comanda (observat cu
  Get-CimInstance Win32_Process) - opriti doar parintele (ex.
  Stop-Process pe PID-ul intors de Start-Process) NU opreste si copilul,
  ramane un proces python.exe orfan in fundal, tinand fisiere blocate
  (ex. data/nids.db). la verificari manuale viitoare, opriti intai
  copiii (Get-CimInstance Win32_Process -Filter "ParentProcessId=<pid>")
  apoi parintele

- warning inofensiv la pornire: `QFont::setPointSize: Point size <= 0
  (-1), must be greater than 0` - vine din interactiunea intre
  DARK_STYLESHEET (seteaza `font-size: 13px`, adica PIXELI) si
  pyqtgraph, care incearca sa deriveze fontul etichetelor de pe axe din
  pointSize() (gaseste -1 cand fontul e setat pe pixeli, nu pe puncte).
  doar cosmetic, nu afecteaza functionalitatea - nu merita efortul de
  reparat acum

## de retinut pentru testare manuala (stare curenta, 2026-08-23)

- ML-ul in monitorizarea live se reevalueaza doar la fiecare 5 secunde
  (nu instant per pachet) - normal sa nu vezi un eveniment ML imediat
  dupa ce apare o conexiune noua, asteapta pana la 5s
- modelul local NU mai porneste de la zero la fiecare sesiune - continua
  de unde a ramas (persistat in data/models/local_model_state.joblib).
  daca ai testat deja destul ca sa treaca de MIN_TRAINING_SAMPLES=50,
  sesiunile urmatoare pornesc direct in modul activ, nu in invatare -
  normal, nu bug. daca vrei sa testezi cold start-ul din nou, sterge
  fisierul de mai sus
- butonul de simulare cere monitorizarea live pornita INAINTE - altfel
  arata doar un mesaj, nu face nimic (traficul generat nu ar fi vazut
  de nimeni daca nimic nu asculta)
- pentru testarea blocarii de IP: "netsh advfirewall" cere drepturi de
  administrator - daca aplicatia nu ruleaza ca admin, blocarea va esua
  (verifica daca apare mesaj de eroare potrivit in loc de crash)
- pentru inspectia unei conexiuni (click-dreapta in tab-ul "Trafic"):
  daca modelul local e inca in invatare, tot arata comparatia cu
  bufferul curent (chiar fara predictie formala) - e intentionat, nu bug
- exportul de raport (Loguri) respecta filtrul de sursa curent - daca ai
  o sursa selectata in dropdown, exportul contine DOAR cronologia aceleia

## probleme de anticipat (vezi si CONTEXT-nids.md)

fals-pozitive, trafic criptat, volum mare de trafic, concept drift,
feature extraction gresit, cold start model local, calibrare scoruri
