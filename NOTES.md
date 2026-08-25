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

## BUG REAL gasit de user si reparat: nu se putea analiza o conexiune blocata manual, din Loguri

user a blocat manual o conexiune ML (click dreapta pe un eveniment din
Dashboard -> "Blocheaza"), apoi a incercat sa deschida analiza completa
din randul "blocare manuala" aparut in Loguri - nu se intampla nimic.

cauza: `_block_event_source()` crea un `Event` nou ("blocare manuala")
fara sa mosteneasca NIMIC din evenimentul original care a declansat
blocarea - nici dest_ip/porturi/protocol, nici assessment_json (poza
completa a analizei ML, deja calculata la momentul respectiv). desi
originea blocarii ESTE o conexiune analizata, noul eveniment nu avea nicio
legatura cu ea - cadea exact in cazul "acest eveniment nu are o conexiune
ML asociata", desi ar fi trebuit sa aiba.

fix: `_block_event_source()` copiaza acum dest_ip/src_port/dest_port/
protocol/assessment_json de pe evenimentul original pe noul eveniment de
"blocare manuala" - Dashboard are deja obiectul `Event` complet la
indemana (e cel stocat pe itemul din `_event_list`, cu tot cu
assessment_json daca a fost generat de ML), doar nu era propagat mai
departe. acum click-dreapta -> "Analizeaza aceasta conexiune cu ML" pe
randul de "blocare manuala" deschide acelasi dialog complet ca pe
evenimentul original.

## BUG REAL gasit de user si reparat: selectia din Loguri "aluneca" la refresh

user a semnalat: selecteaza un rand in tabelul din Loguri, apare un
eveniment nou, iar randul ramane vizual selectat dar acum arata alt
eveniment.

cauza: `LogsPanel._refresh_table()` reconstruieste tabelul integral la
fiecare 2 secunde (interogare noua din SQLite, `setRowCount` +
`setItem` pentru fiecare celula) - Qt pastreaza selectia pe INDEXUL de
rand, nu pe identitatea itemului. cum `recent()` intoarce cele mai noi
evenimente PRIMELE (`ORDER BY id DESC`), un eveniment nou aparut e
inserat pe randul 0 si impinge tot ce era mai vechi cu un rand mai jos -
randul ramas "selectat" (acelasi index) arata acum alt eveniment.

fix: `StoredEvent` are acum campul `id` (PRIMARY KEY-ul din SQLite,
adaugat la finalul `_SELECT_COLUMNS`/dataclass - `id: int = -1` implicit
pentru constructiile sintetice din teste, care nu vin din DB).
`LogsPanel._refresh_table()` retine id-urile randurilor selectate
INAINTE de reconstructie (`_selected_entry_ids()`) si re-aplica selectia
DUPA (`_restore_selection()`), gasind randul unde a ajuns acum acelasi
id - selectia "urmareste" evenimentul, nu pozitia lui in tabel.

## BUG REAL gasit de user si reparat: crash la inchidere - refresh dupa EventStore.close()

user a vazut in consola, dupa ce a inchis aplicatia:
`sqlite3.ProgrammingError: Cannot operate on a closed database`, venind
din `LogsPanel._refresh()` -> `distinct_sources()`.

cauza: `LogsPanel` are propriul `QTimer` (refresh la 2s), pornit in
`__init__` si NICIODATA oprit explicit. `MainWindow.closeEvent()` apela
`self._event_store.close()`, dar timer-ul QTimer al LogsPanel ramanea
activ - un tick programat mai putea rula DUPA close(), lovind o conexiune
SQLite deja inchisa. (ResponsePanel/MlPanel au acelasi tipar de timer,
dar interogheaza BlockManager/DashboardPanel, care nu au un "close" care
sa le invalideze - de-asta doar Loguri crapa)

fix: `LogsPanel.stop()` (metoda noua) opreste timer-ul explicit.
`MainWindow.closeEvent()` o apeleaza INAINTE de `event_store.close()` -
ordine care elimina complet cursa, pentru ca totul ruleaza pe acelasi
thread UI (fara concurenta reala, doar ordine gresita de apeluri).

## BUG REAL gasit de user si reparat: crash la blocare fara drepturi de Administrator

user a incercat sa blocheze manual o adresa IP (click dreapta pe un
eveniment din Dashboard -> "Blocheaza") si aplicatia a crapat cu un
traceback in terminal, in loc sa arate o eroare in UI.

cauza: `add_block_rule()` (nids/response/block.py) ruleaza `netsh
advfirewall firewall add rule ...` cu `check=True` - pe Windows, aceasta
comanda cere drepturi de Administrator; aplicatia userului rula dintr-un
terminal normal, deci `netsh` a refuzat si `subprocess.run` a aruncat
`CalledProcessError`. acea exceptie nu era prinsa NICAIERI pe drum:
`BlockManager.block()` -> `DashboardPanel._block_event_source()` -> lambda
conectata la `action.triggered` - a scapat pana in bucla de evenimente
Qt si a crapat aplicatia.

fix, in doua straturi:
- `BlockManager` (nids/response/manager.py) nu mai lasa NICIO exceptie de
  la backend-ul injectat (add_rule/remove_rule) sa scape necontrolat:
  - `block()`: orice exceptie de la `add_rule` e prinsa si re-aruncata ca
    `BlockRuleError` (exceptie proprie, catchabila explicit de UI, nu mai
    leaga BlockManager de detalii specifice netsh). starea interna ramane
    curata la esec - IP-ul NU ajunge in `_blocked`/`history()`
  - `_unblock_locked()`: orice exceptie de la `remove_rule` e prinsa si
    IGNORATA (best-effort) - altfel un esec la deblocare ar lasa IP-ul
    "blocat pentru totdeauna" fara nicio cale de a-l scoate din UI, sau
    ar opri la jumatate bucla din `shutdown()` (ar lasa unele reguli
    active si ar impiedica inchiderea curata a event_store-ului). o
    regula de firewall ramasa e mai reparabila decat o stare interna blocata
- `DashboardPanel._block_event_source()` prinde `BlockRuleError` explicit,
  arata un mesaj clar in bara de status ("...ruleaza aplicatia ca
  Administrator pentru blocare de firewall") si salveaza o intrare
  "blocare esuata" in Loguri (audit trail, la fel ca orice alta actiune)
  in loc de "blocare manuala"

## BUG REAL gasit de user si reparat: pierderea modelului local la inchidere

user a observat ca modelul local, care avea 85+ conexiuni antrenate
inainte sa inchida aplicatia, repornea de la 0/50 la deschiderea urmatoare
- desi persistenta (save/load) era deja implementata (pasul 13).

cauza: MainWindow.closeEvent() apela doar stop_monitoring() (asincron -
doar semnaleaza thread-ul sa se opreasca, nu asteapta). salvarea
modelului local se intampla in _on_thread_finished(), declansat de
semnalul QThread.finished - dar acel semnal e livrat prin coada de
evenimente a thread-ului principal, care se putea sa nu mai apuce sa
proceseze nimic inainte ca aplicatia sa se inchida complet. rezultat:
_on_thread_finished() (deci si salvarea) nu rula NICIODATA la inchidere,
doar la apasarea manuala a butonului "Opreste monitorizare" (unde
aplicatia ramane deschisa si event loop-ul continua sa ruleze normal).

fix: DashboardPanel.shutdown() (metoda noua, distincta de
stop_monitoring()) - opreste SINCRON: semnaleaza thread-ul, asteapta
efectiv cu QThread.wait(3000), apoi salveaza modelul local DIRECT, fara
sa se bazeze pe semnalul finished. MainWindow.closeEvent() foloseste
acum shutdown() in loc de stop_monitoring(). stop_monitoring() (asincron)
ramane neschimbat pentru click normal pe buton - acolo async e corect,
nu vrem sa inghetam UI-ul 3 secunde la un simplu stop manual.

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
