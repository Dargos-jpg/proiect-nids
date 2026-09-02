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
