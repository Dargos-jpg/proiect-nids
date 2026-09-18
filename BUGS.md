# bug-uri reale gasite de user + fix-uri

istoric separat de NOTES.md (care tine arhitectura/deciziile/features) -
aici doar bug-uri reale gasite in timpul testarii manuale (de user, nu
inventate/anticipate) + cauza radacina + fix-ul aplicat. scop: usor de
gasit "ce s-a stricat si cum s-a reparat" fara sa cauti prin tot jurnalul
de dezvoltare. ordinea e cea in care au fost documentate.

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

## BUG REAL gasit de user: analiza din Loguri esua mereu pentru brute-force/porturi sensibile

user a testat manual brute-force si a observat ca "Analizeaza aceasta
conexiune cu ML" din Loguri nu deschide nimic pentru acel tip de eveniment.

cauza: `event_from_brute_force()` si `event_from_sensitive_port()`
seteaza `dest_ip`/`dest_port` (pentru context/afisare), dar NU `src_port`
- nu exista un singur port sursa asociat unui brute-force (sunt MAI MULTE
incercari, deci mai multe porturi sursa; evenimentul retine doar
numarul, nu lista). `_on_log_analyze_requested()` verifica doar
`entry.dest_ip is None` inainte sa incerce `_analyze_connection()`, care
apeleaza `_find_matching_connection()` - aceasta cere o potrivire EXACTA
pe tot tuplul (src_ip, src_port, dst_ip, dst_port). cu `src_port=None`
si niciun record real avand `src_port=None`, potrivirea esueaza GARANTAT,
de fiecare data, aratand mesajul generic "nu s-a putut identifica
conexiunea" - care, fiind doar text in bara de status (alta zona decat
Loguri), parea identic cu "nu se intampla nimic click-ul".

fix: verificarea explicita `entry.src_port is None` inainte de a incerca
deloc `_analyze_connection()` pentru evenimente din Loguri - arata direct
mesajul "nu are o conexiune ML asociata", fara sa mai incerce o potrivire
imposibila. + mesajul a devenit un QMessageBox (popup), nu doar text in
bara de status - a doua oara cand exact acest tip de confuzie
("nu se intampla nimic" cand de fapt un mesaj apare in alta zona a
ferestrei) a fost raportat de user, merita un semnal mai greu de ratat.

## doua bug-uri reale de layout, gasite de user dupa ce panourile au crescut mult

user a observat ca nu mai poate redimensiona Loguri (jos) in sus, si ca
un panou plutitor inchis din X dispare fara nicio urma vizibila de unde
sa-l recupereze.

- **SignaturesPanel devenise prea inalt** (5 grupuri de setari stivuite -
  port scan, porturi sensibile, brute-force, DNS tunneling, payload) -
  fara scroll intern, inaltimea lui naturala dicta inaltimea MINIMA a
  intregii zone de andocare din dreapta (Semnaturi/ML/Raspuns/Honeypot
  sunt tab-uite impreuna, deci zona trebuie sa incapa cel mai inalt tab),
  ceea ce impiedica redimensionarea Logurilor din alta zona. fix:
  continutul panoului e acum intr-un QScrollArea (minim 120px, restul
  derulabil) - panoul poate fi oricat de mic, nimic nu se pierde, doar
  se deruleaza
- **dock-urile aveau buton de inchidere (X)** - daca userul scotea un
  panou din andocare (float) si il inchidea din X in loc sa-l traga
  inapoi, dispare complet - tehnic recuperabil din meniul "Vizualizare"
  (toggleViewAction e deja legat bidirectional), dar usor de ratat/parea
  pierdut definitiv. fix: `dock.setFeatures()` fara `DockWidgetClosable`
  - raman Movable + Floatable (poti tot sa il scoti din andocare si sa-l
    tragi inapoi), dar fara X nu mai exista actiunea accidentala care sa
    para ireversibila - singura cale de ascundere/afisare ramane meniul
    Vizualizare, care e deja un toggle corect

## fals-pozitive REALE de DNS tunneling, gasite de user pe trafic real

testand brute-force, userul a prins din intamplare 2 fals-pozitive reale
de DNS tunneling: "launcher-public-service-prod06.ol.epicgames.com" si
"service-aggregation-layer-subs.juno.ea.com" - domenii legitime (Epic
Games, EA), dar cu etichete lungi (30 caractere) si compuse din cuvinte
cu cratima, care intamplator au entropie mare.

descoperire tehnica importanta la calcularea entropiei exacte:
"launcher-public-service-prod06" are entropie 4.01 - MAI MARE decat un
exemplu de date hex-encodate real (3.82)! un prag de entropie simplu NU
poate separa curat domenii tehnice legitime de date chiar encodate - se
suprapun ca interval.

fix, bazat pe un fapt tehnic despre tunneling-ul real, nu pe reglaj
arbitrar de prag: DNS tunneling foloseste aproape mereu base32 sau hex
pentru codificare, NICIODATA base64 - base64 nu supravietuieste
case-insensitivity-ul DNS (majuscule/minuscule se pot pierde la
rezolvare). niciunul din alfabetele base32/hex nu contine cratima sau
alt separator. adaugat `label.isalnum()` ca filtru inainte de verificarea
de entropie in `_suspicious_reason()` - orice eticheta cu cratima (sau
alt caracter non-alfanumeric) e aproape sigur un nume ales de un
om/serviciu, nu date encodate. exclude ambele fals-pozitive reale, fara
sa afecteze detectia pe date chiar encodate (hex/base32, fara cratima).

## bug de mediu (nu de cod) gasit la testarea brute-force: Windows loopback fast path

user a targetat propriul IP real din LAN (192.168.1.130, port 22) de 6 ori
cu `Test-NetConnection`, apoi a verificat in Trafic - zero pachete pe port
22, din 718 pachete capturate in total.

cauza: optimizarea interna Windows "loopback fast path" ruteaza conexiunile
catre IP-ul REAL propriu al masinii (nu doar 127.0.0.1) direct intern, fara
sa treaca prin placa de retea fizica pe care asculta Npcap/Scapy - deci
niciun pachet de vazut, indiferent de logica de detectie. NU e un bug de
cod: Honeypot (socket real de ascultare OS, nu captura de pachete) a
functionat corect testat tot prin loopback, ceea ce a ajutat sa izolam ca
problema e specifica capturii de pachete, nu logicii aplicatiei.

concluzie comunicata userului: nereparabil in codul aplicatiei; logica de
detectie brute-force ramane validata de ~15 teste automate; modelul de
amenintare realist (atacator de pe ALTA masina din retea) nu e afectat.
test cross-device real (alt dispozitiv din retea) ar fi confirmarea
definitiva, dar nu a mai fost necesar - userul s-a declarat multumit de
diagnostic.

## test cu semnatura de fake veche, ratat la un lot anterior de modificari

la rularea completa a suitei de teste inainte de sesiunea de honeypot ->
reantrenare, `tests/test_dashboard_simulation.py::test_simulate_while_monitoring_runs_and_updates_status`
esua cu `_idle_capture() got an unexpected keyword argument 'on_arp'`.

cauza: exact tiparul deja documentat de "drift de semnatura" (vezi NOTES.md,
sectiunea semnaturi noi) - de fiecare data cand `capture_live()`/
`LiveCaptureThread` a capatat un parametru optional nou (`on_arp`, `on_dns`,
`on_payload`), toate fake-urile din teste cu semnatura fixa trebuiau
actualizate manual. `test_live_capture_thread.py`, `test_dashboard_live_monitoring.py`
si `test_dashboard_ml_settings.py` fusesera actualizate la momentul respectiv,
dar `test_dashboard_simulation.py::_idle_capture()` a fost ratat din lot.

fix: adaugat `on_arp=None, on_dns=None, on_payload=None` la semnatura
`_idle_capture()`, la fel ca la celelalte fake-uri. gasit prin rularea
suitei complete (423 teste) inainte de commit, nu prin testare manuala -
util de retinut: dupa orice schimbare de semnatura pe o functie cu multe
fake-uri de test, merita cautat explicit toate locurile care o inlocuiesc
(`grep` dupa numele functiei), nu doar cele deja stiute.

## bug prins la scrierea testelor (nu la testare manuala): banner grab cu doua conexiuni separate la scanner-ul de vulnerabilitati

la implementarea `scan_host()` (nids/scanner/vulnerability_scan.py), prima
varianta facea DOUA conexiuni TCP separate per port deschis: una pentru
`connect_ex()` (doar ca sa verifice ca portul e deschis, apoi inchisa
imediat), si una noua, separata, pentru `_grab_banner()`.

testul `test_scan_host_finds_open_port_with_banner` (server de test simplu,
`socket.listen(1)`, accepta o singura conexiune si trimite banner-ul) a
esuat cu banner gol - desi serverul de test CHIAR trimitea banner-ul.

cauza: cu backlog=1, cele doua conexiuni separate (verificare + banner)
ajung intercalate nedeterminist in coada de accept a serverului - server-ul
accepta oricare ajunge prima (adesea cea de verificare, deja inchisa de
client pana apuca sa trimita ceva), iar a doua conexiune (cea reala, pentru
banner) poate fi refuzata sau ignorata. cu alte cuvinte: comportamentul
depindea de o cursa intre doua conexiuni, nu de logica aplicatiei.

fix: banner-ul se citeste acum pe ACEEASI conexiune care a confirmat ca
portul e deschis (`_read_banner(sock)` primeste socket-ul deja conectat),
nu se mai deschide o a doua conexiune deloc - mai eficient (jumatate din
conexiuni) SI corect (nicio cursa posibila). exact genul de bug pe care
scrierea testelor cu un server real (nu un mock) l-a scos la iveala inainte
sa ajunga cod livrat - testul a fost cel care a gasit problema, nu userul.

## bug real la prima rulare: scriptul de pregatire CSE-CIC-IDS2018 respingea 100% din date

`scripts/prepare_cse_cic_ids2018.py` (esantionare stratificata pentru al
doilea model expert, vezi NOTES.md/DATASET-COMPARISON.md) a rulat pana la
capat (a procesat toate cele 10 fisiere, ~6.5GB) fara nicio eroare vizibila
in timpul procesarii - dar la final a crapat cu `ValueError: No objects to
concatenate`, semn ca NICIUN rand nu a supravietuit curatarii, din niciun
fisier.

cauza: `_clean_chunk()` verifica finitudinea (`np.isfinite`) pe TOATE
coloanele in afara de "Label", inclusiv `Timestamp` - un string de tip
data ("01/03/2018 08:17:11"), NU un numar. `pd.to_numeric(errors="coerce")`
transforma orice string neconvertibil in NaN, deci coloana Timestamp
devenea NaN pentru FIECARE rand, iar verificarea `.all(axis=1)` (toate
coloanele finite) respingea automat 100% din date, indiferent de fisier.

gasit prin verificare directa pe un singur fisier mic (`_clean_chunk()`
apelat manual pe primul chunk din Thursday-01-03), nu prin re-rularea
oarba a intregului job de 6.5GB - a confirmat fix-ul in cateva secunde
inainte de a re-porni procesarea completa (~10+ minute).

fix: `Timestamp` eliminat explicit (`chunk.drop(columns=["Timestamp"])`)
INAINTE de verificarea de finitudine, nu doar mai tarziu in pipeline -
oricum nu ajunge in schema finala (nu e in COLUMN_RENAME_MAP din
nids/ml/modern/dataset.py, e identificare, nu feature). lectie: la orice
verificare de tip "toate coloanele trebuie sa fie X", merita explicit
listate coloanele la care chiar se aplica, nu presupus ca "restul
coloanelor" inseamna automat "toate sunt de tipul asteptat".

## bug real gasit dupa prima antrenare: plafon egal pe toate clasele a inversat raportul normal/atac

prima antrenare reala a modelului expert modern (CSE-CIC-IDS2018, dupa
fix-ul de mai sus) a rulat cu succes, dar a scos un rezultat suspect:
acuratete generala 92.6%, dar precizie/recall doar 62%/65% pe clasa
"normal", fata de 96%/96% pe "atac" - un model care recunoaste atacurile
foarte bine, dar confunda des traficul normal cu atac.

cauza: `SAMPLES_PER_CLASS = 50_000` se aplica UNIFORM pe toate cele 15
clase, inclusiv "Benign" - dar "Benign" e o singura clasa in schema binara
finala (normal vs atac), in timp ce cele 8 clase de atac cu peste 50k
randuri (HOIC, LOIC-HTTP, Hulk, Bot, FTP-BruteForce, SSH-Bruteforce,
Infilteration, SlowHTTPTest) au fost fiecare plafonate tot la 50k -
verificat direct in fisierul de antrenare rezultat: 40,000 randuri Benign
vs ~364,000 randuri atac (raport 9:1) - INVERSUL realitatii (83% din
traficul real e normal). modelul a invatat sa "vada" mult mai putine
exemple de normal decat de atac, si a devenit predispus sa etichetize gresit
normal ca atac.

fix: `_PER_CLASS_CAPACITY_OVERRIDES = {"Benign": 450_000}` in
scripts/prepare_cse_cic_ids2018.py - Benign primeste un plafon separat,
apropiat de totalul claselor de atac (~455k), nu acelasi plafon ca o
singura clasa de atac. dupa re-rulare: precizie/recall pe "normal" a urcat
la 91%/96% (de la 62%/65%), acuratete generala aproape neschimbata (93.2%
fata de 92.6%) - dovada ca problema nu era "cat de bun e modelul", ci
"cat de reprezentativ e setul de antrenare pentru cele DOUA clase finale
(normal/atac), nu pentru cele 15 categorii brute de eticheta".

lectie: la esantionare stratificata pentru o problema BINARA (normal/atac)
derivata dintr-un set cu MULTE etichete brute, plafonul per-clasa trebuie
gandit relativ la gruparea FINALA (2 clase), nu la numarul brut de
categorii din date - un plafon "corect" per categorie bruta poate fi
complet gresit per clasa finala daca o singura categorie bruta (Benign)
reprezinta 100% dintr-o parte a clasificarii binare.

## bug real gasit dupa integrarea in UI: modelul modern de 1.18 GB a incetinit toata suita de teste de la ~30s la peste 5 minute

dupa ce modelul expert modern a fost legat in `DashboardPanel` (Faza 3 -
"a doua opinie" in ConnectionInspectorDialog), rularea suitei complete de
teste a urcat brusc de la ~30-70s la **323 secunde** (peste 5 minute),
fara nicio schimbare vizibila in ce testau testele.

cauza: `DashboardPanel.__init__()` incearca sa incarce ambele modele
expert (vechi + modern) la fiecare instantiere - zeci de teste din multe
fisiere (`test_dashboard_*.py`) construiesc `DashboardPanel` direct, deci
fiecare din ele incarca acum SI modelul modern de pe disc. verificat:
`data/models/modern_expert_random_forest.joblib` avea **1.18 GB**
(fata de 20.7 MB la modelul vechi, NSL-KDD/125k randuri) - arborii
RandomForest crescusera nelimitat (fara `min_samples_leaf`) pe 724,123
randuri de antrenare, mult mai multe decat NSL-KDD. deserializarea acestui
fisier, repetata la fiecare test, explica intreaga incetinire.

fix: `min_samples_leaf` adaugat la `RandomForestClassifier` in
`scripts/train_modern_expert_model.py` - masurat empiric (acelasi set de
date, doar variind acest parametru):
- `min_samples_leaf=5` -> 454 MB, acuratete 0.9439
- `min_samples_leaf=20` -> 152 MB, acuratete 0.9442
- `min_samples_leaf=50` -> 68 MB, acuratete 0.9435

acuratetea a ramas practic neschimbata (arborii nelimitati erau doar
inutil de mari/adanci, nu "mai buni" - de fapt usor supraadaptati, 0.9435
e in limita normala de variatie) - ales 50, cea mai mica dimensiune fara
nicio pierdere reala de semnal. suita de teste a revenit la ~36-55s.

lectie: un model antrenat pe un set de date semnificativ mai mare decat
precedentul (aici 5.8x) merita verificat explicit la dimensiunea
fisierului salvat, nu doar la acuratete - un RandomForest fara limita de
adancime creste cu volumul de date mult mai repede decat utilitatea lui
reala, si dimensiunea mare devine o problema de PERFORMANTA (incarcare
lenta) inainte sa devina vizibila ca problema de acuratete.

## inca doua fake-uri de captura cu semnatura veche, ratate la acelasi lot de modificari

dupa ce schimbarea `strict_reporting` implicit (NOTES.md) a scos la iveala
un test picat (`test_dashboard_live_ml.py::test_ml_tick_adds_event_to_dashboard`,
fix real - vezi NOTES.md), am cautat explicit (`grep def _idle_capture`) alte
locuri cu acelasi tipar de "drift de semnatura" documentat mai devreme (vezi
mai sus, "test cu semnatura de fake veche").

gasite doua in plus, nedeclansand nicio eroare vizibila pana acum: `_idle_capture()`
din `test_dashboard_live_ml.py` si din `test_dashboard_shutdown.py`, ambele
fara `on_arp=None, on_dns=None, on_payload=None`. nu esuau explicit pentru ca
`LiveCaptureThread.run()` prinde orice exceptie si o transforma in semnalul
`error` (nimeni nu asertat pe el in aceste teste) - eroarea de semnatura era
"inghitita" tacut, nu vizibila in rezultatul testului.

fix: adaugate cele trei parametri lipsa la ambele. lectie confirmata:
cautarea explicita dupa nume de functie, nu doar fixarea locului unde a picat
un test, gaseste probleme latente inainte sa produca o eroare vizibila.

## bug real gasit dupa reantrenarea honeypot mutata pe modelul modern: teste nedeterministe din cauza celui de-al doilea DEFAULT_STATE_PATH

dupa ce reantrenarea din honeypot a fost mutata sa antreneze modelul
MODERN (`nids/ml/modern/retrain.py`, in loc de cel vechi), rularea suitei
complete de teste a scos 2 esecuri noi in `test_dashboard_live_ml.py`,
desi acel fisier nu fusese atins de schimbare.

cauza: Faza 6 (DATASET-COMPARISON.md) a introdus un AL DOILEA model local
persistent (`ModernLocalModelManager`, propriul `DEFAULT_STATE_PATH` -
`data/models/modern_local_model_state.joblib`). testele care apeleaza
`_start_monitoring()` monkeypatch-uiau deja `nids.ml.local.learning.DEFAULT_STATE_PATH`
(cel vechi) catre `tmp_path`, dar NU si echivalentul modern - deci
`ModernLocalModelManager.load_or_new()` incarca fisierul REAL de pe disc,
care exista deja cu date reale (402 conexiuni, acumulate de user in
sesiunile de testare manuala anterioare). testele presupuneau un model
local "inca invata" (cold start) si primeau unul deja activ, cu 402
conexiuni reale amestecate in rezultat.

fix: acelasi monkeypatch, dublat, in toate cele 5 fisiere de teste care
apeleaza `_start_monitoring()` (`test_dashboard_shutdown.py`,
`test_dashboard_ml_settings.py`, `test_dashboard_live_ml.py`,
`test_dashboard_live_monitoring.py`, `test_dashboard_simulation.py`) -
`nids.ml.modern.learning.DEFAULT_STATE_PATH` catre `tmp_path`, la fel ca
cel vechi.

lectie: exact tiparul deja documentat de "drift" la introducerea unui
sistem paralel nou (ca la semnaturile de fake capture) - orice test care
izoleaza o resursa persistenta (fisier de stare, model salvat) trebuie
revizitat cand apare un AL DOILEA sistem cu aceeasi forma de persistenta,
nu doar codul de productie.

## bug de mediu (nu de cod propriu): suita completa de teste crapa intermitent cu segfault in joblib

dupa adaugarea extinderii graficului de trafic (fara nicio legatura cu ML),
rularea suitei COMPLETE de teste a inceput sa crape reproductibil cu
"Segmentation fault", mereu in interiorul backend-ului de threading al
`joblib` (folosit de `RandomForestClassifier`/`IsolationForest` la
`predict()`/`fit()` cu `n_jobs=-1`) - trace-ul C arata sute de thread-uri
worker acumulate (`Thread-554`, `Thread-553`, ...) in momentul crash-ului.

investigat inainte sa se presupuna o cauza: fisierul unde crapa
(`test_modern_hybrid_analysis.py`) trece CURAT, de 3 ori la rand, cand e
rulat izolat - deci nu e un bug in acel test sau in codul din spate.
crash-ul apare DOAR la rularea suitei complete (500+ teste), semn clar de
ACUMULARE - multe teste creeaza/antreneaza/prezic cu RandomForest/Isolation
Forest de-a lungul rularii, fiecare cu propriul thread-pool joblib; ceva
in interactiunea dintre acest volum si acest build de Python (3.14, foarte
recent) pe Windows nu elibereaza corect thread-urile intre apeluri.

fix: `tests/conftest.py` (nou) - seteaza `LOKY_MAX_CPU_COUNT=1` si
`OMP_NUM_THREADS=1` inainte de orice import, pentru toata sesiunea de
teste. codul de PRODUCTIE (scripturile de antrenare, retrain.py) ramane
neschimbat - tot foloseste `n_jobs=-1` pentru viteza reala pe seturi mari
de date; doar suita de teste (modele-jucarie, cateva randuri) forteaza
executie seriala, eliminand crearea/distrugerea repetata de thread-pool-uri.
confirmat stabil pe 3 rulari complete consecutive dupa fix (597 teste).

lectie: cand un crash apare doar la scara completa, nu la nivel de test
individual, cauza rareori sta in testul unde se manifesta - investigheaza
intai daca se reproduce izolat, inainte sa presupui ca schimbarea cea mai
recenta (aici, un widget Qt fara nicio legatura cu ML) e vinovata.

## BUG REAL gasit de user: monitorizarea live devine "incredibil de lag" dupa sesiuni lungi (350k+ pachete, 2 ore)

user a tinut monitorizarea live pornita ~2 ore, a ajuns la 350.000+ pachete
capturate si a observat aplicatia devenind foarte lenta. semnal decisiv,
oferit chiar de user inainte sa apuc sa intreb: lag-ul disparea IMEDIAT la
apasarea "Opreste monitorizare" - insemnand ca ceva legat STRICT de
monitorizarea activa (nu Loguri, nu Trafic, nu altceva) era cauza.

cauza: `LiveHybridAnalyzer._packets` (vechi) si `ModernLiveHybridAnalyzer._packets`
(modern) cresteau NELIMITAT pe toata durata sesiunii - fiecare pachet nou
era doar adaugat, niciodata scos. `evaluate()`, apelat periodic (implicit
la 5 secunde) de `DashboardPanel._on_ml_evaluation_tick()`, reprocesa
INTEGRAL toata lista la fiecare apel (`extract_nsl_kdd_style_features()`/
`extract_cicflow_features()` pe tot ce exista pana atunci), ca sa poata
identifica ce conexiuni sunt noi. asta insemna cost per-tick crescator
constant cu durata sesiunii - practic patratic in timp total (mai multe
tick-uri, fiecare tot mai scump). era deja o limitare CUNOSCUTA, notata
explicit in docstring-ul `LiveHybridAnalyzer` inca de la construirea lui
("creste cu volumul de trafic") - dar Faza 6 (DATASET-COMPARISON.md) a
agravat-o direct: ambele analizoare (vechi, pentru antrenare continua in
fundal + modern, principal) ruleaza acum `evaluate()` la FIECARE tick,
dublând efectiv costul care era deja o problema latenta.

fix: `MAX_BUFFERED_PACKETS = 20_000` in ambele module
(`nids/core/live_hybrid.py`, `nids/ml/modern/live_hybrid.py`) -
`self._packets` a devenit `collections.deque(maxlen=...)` in loc de
`list` simplu, o fereastra glisanta pe ULTIMELE pachete (evictie O(1),
spre deosebire de `list.pop(0)`). NU afecteaza deduplicarea - `_evaluated_connections`/
`_evaluated_flows` raman seturi separate, neplafonate (doar tupluri, cost
neglijabil), deci o conexiune tot e evaluata o singura data, atata timp
cat pachetele ei mai sunt in fereastra (in practica mereu, tick-urile
ruleaza mult mai des decat timpul necesar ferestrei de 20k sa se umple).

validat empiric dupa fix: 350.000 de pachete + 70 de tick-uri periodice
(simuland exact scenariul userului) proceseaza in **0.52 secunde** total,
bufferul ramane plafonat corect la 20.000.

nota separata, NU inca reparata: `DashboardPanel._all_packets` (folosit
pentru "Analizeaza aceasta conexiune"/"Reconstruieste conexiunea" la
cerere, nu periodic) ramane neplafonat - creste in continuare nelimitat pe
durata unei sesiuni live. nu cauzeaza lag CONTINUU (nu ruleaza pe un timer,
doar la click), dar ar face un singur click de analiza lent dupa o sesiune
foarte lunga, plus consum de memorie crescator. lasat deliberat neatins in
acest fix - PCAP-urile incarcate folosesc ACEEASI variabila si au nevoie de
lista COMPLETA (nu se poate plafona global fara sa rupa analiza PCAP) -
ar necesita o solutie separata (ex: doar pentru path-ul live), nu inclusa
aici ca sa nu creasca riscul acestei modificari.

## BUG REAL gasit de user: analiza unui rand din Loguri dintr-o sesiune anterioara "redimensioneaza" fereastra principala, fara sa apara vreun dialog

user a incercat sa analizeze cu ML un rand din Loguri provenit dintr-o
sesiune anterioara (aplicatia repornita intre timp) - in loc de dialogul
de analiza sau un mesaj clar, doar fereastra principala se redimensiona
vizibil, fara nicio alta reactie. randuri noi (din sesiunea curenta) se
analizau normal, fara nicio problema.

cauza: NU era o exceptie ascunsa. `_on_log_analyze_requested()` ->
`_analyze_connection()` functiona corect - `_all_packets` (in memorie, nu
persistat) nu mai contine pachetele unei sesiuni vechi, deci se ajungea
corect pe ramura `self._status_label.setText("nu s-a putut identifica
conexiunea - probabil traficul brut nu mai e disponibil (alta sesiune sau
pachete deja iesite din istoric)")` - cel mai lung mesaj de status din
toata aplicatia. `self._status_label` era un `QLabel` simplu, fara word
wrap, asezat in bara de sus (`top_bar`, un `QHBoxLayout`) - fara wrap,
latimea minima a unui QLabel e latimea intregului text pe un singur rand,
deci layout-ul cerea mai mult spatiu orizontal decat avea fereastra, iar
Qt marea fereastra principala ca sa incapa. orice alt mesaj de status
existent era suficient de scurt incat sa nu declanseze vizibil asta -
de-asta doar acest caz specific parea stricat.

fix: `self._status_label.setWordWrap(True)` + `setMaximumWidth(400)` in
`DashboardPanel.__init__` (`nids/ui/widgets/dashboard_panel.py`) - labelul
acum se infasoara pe mai multe randuri in loc sa ceara latime nelimitata,
deci fereastra principala nu mai creste indiferent cat de lung e mesajul.
comportamentul de fond (nu exista dialog pentru o conexiune din alta
sesiune, doar un mesaj de status) ramane neschimbat si e corect - problema
era exclusiv vizuala (`test_status_label_has_word_wrap_enabled`,
`test_log_analyze_requested_for_previous_session_connection_shows_message`
in `tests/test_dashboard_analyze.py`).

## BUG REAL gasit de user: coloana "prefix BGP" din dialogul de identificare IP-uri era taiata

dupa adaugarea coloanelor AS/organizatie/tara/prefix BGP (vezi NOTES.md,
lookup Team Cymru), user a semnalat ca prefixul BGP nu se vedea complet
(ex: "104.18.32.0/..." in loc de "104.18.32.0/20") fara sa redimensioneze
manual fereastra.

cauza: doar coloanele "nume de host (PTR)" si "organizatie/ISP" aveau un
resize mode explicit (`Stretch`) - restul (IP, AS, tara, prefix BGP)
ramaneau pe modul implicit al `QTableWidget` (latime fixa, nu neaparat
suficienta pentru continut).

fix: `IpLookupResultsDialog` (`nids/ui/widgets/ip_lookup_dialog.py`)
seteaza acum explicit `ResizeToContents` pentru IP/AS/tara/prefix BGP
(coloane cu continut scurt si de latime relativ constanta) - se
redimensioneaza automat dupa continutul efectiv - si pastreaza `Stretch`
doar pe hostname/organizatie (singurele cu lungime variabila mare).
latimea implicita a dialogului a crescut la 1000px (de la 760px).

## limitare cunoscuta, acum inchisa: DashboardPanel._all_packets neplafonat pe sesiuni live lungi

notata (dar deliberat neatinsa) la fix-ul de lag din monitorizarea live
(vezi mai sus): spre deosebire de bufferul intern al analizoarelor
(`LiveHybridAnalyzer`/`ModernLiveHybridAnalyzer._packets`, deja plafonat la
20.000), `DashboardPanel._all_packets` - folosit pentru "Analizeaza aceasta
conexiune"/"Reconstruieste conexiunea" la cerere, din Trafic - ramanea o
lista simpla, neplafonata. nu cauza lag continuu (nu ruleaza pe un timer),
dar ar fi facut un singur click de analiza tot mai lent pe o sesiune foarte
lunga (reproceseaza toata lista), plus consum de memorie crescator.

de la Faza 7 (DATASET-COMPARISON.md - persistarea assessment_json si
pentru modelul modern), evenimentele deja RAPORTATE nu mai depind deloc de
aceasta lista (au propria "poza" salvata) - singurul rol ramas al ei e
analiza directa a unei conexiuni INCA neevaluate, din Trafic, sau
reconstructia packet-forensics - ambele despre trafic RECENT, nu istoric
vechi. asta a facut plafonarea sigura de facut acum.

fix: `MAX_ALL_PACKETS = 50_000` (`nids/ui/widgets/dashboard_panel.py`) -
`self._all_packets` devine `collections.deque(maxlen=...)` DOAR la
`_start_monitoring()` (calea live). `_on_load_clicked()` (PCAP incarcat)
ramane NEATINS - atribuie in continuare o lista simpla, completa, din
`read_pcap()` (are nevoie de tot fisierul, nu de o fereastra glisanta).
consumatorii (`extract_nsl_kdd_style_features`, `extract_cicflow_features`,
`packets_for_connection`) primesc explicit `list(self._all_packets)`, la
fel ca in `LiveHybridAnalyzer.evaluate()` - desi toate trei doar itereaza
(ar functiona si direct pe deque), conversia explicita pastreaza acelasi
tipar folosit deja in tot proiectul.
