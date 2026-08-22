# context proiect - NIDS hibrid

## ce e proiectul

sistem de detectie a intruziunilor in retea (NIDS), cu scop dublu:
proiect personal de portofoliu tehnic (relevant pentru profil securitate
retea) si unealta reala, nu doar un exercitiu academic cu un dataset fix.

## arhitectura pe straturi

```
captura pachete (live sau PCAP)
        |
   parsare + extragere metadate (IP, port, protocol, dimensiune, timing)
        |
   +----+----+
   |         |
semnaturi   features pentru ML
   |         |
 match?   model expert + model local (vezi mai jos)
   |         |
   +----+----+
        |
   eveniment generat (severitate, tip, sursa)
        |
   dashboard live
        |
   raspuns: automat (safe/reversibil) SAU manual (user alege)
        |
   logging + istoric (audit trail)
```

## detectie - doua straturi

**semnaturi** (nucleu, functional independent de ML):
port scanning, brute-force pe servicii cunoscute (SSH/RDP/web login),
semnaturi malware/exploit in payload, ARP spoofing, DNS tunneling

**ML - arhitectura dual-model, nu single-model**:
- model "expert": pre-antrenat pe dataset public cunoscut (CICIDS2017
  sau NSL-KDD ca punct de plecare, NSL-KDD mult mai mic si usor de
  folosit initial). stie pattern-uri de atac generice.
- model "local": antrenat doar pe traficul capturat de utilizator pe
  reteaua lui. nu stie nimic despre atacuri "din carte", invata doar
  ce e normal pentru reteaua asta specifica.
- cele doua modele NU sunt un ensemble clasic care doar voteaza -
  dezacordul dintre ele e el insusi semnal util:
  - expert=atac, local=normal -> posibil fals-pozitiv al modelului expert
  - local=anomalie, expert=nimic cunoscut -> cel mai interesant caz,
    posibil atac nou/personalizat care nu se potriveste cu pattern-uri
    publice
  - ambele de acord -> incredere mare

modulul ML e customizabil vizual de utilizator, stil Weka: alege ce
features extrage, ce algoritm foloseste (K-Means, Random Forest, SVM,
Isolation Forest), configureaza parametri, vede rezultat grafic.

## nivel de raspuns

- automat, dar strict safe/reversibil: blocare IP temporara cu
  auto-expirare, rate limiting - niciodata actiuni permanente sau
  distructive
- manual, human-in-the-loop: dashboard arata evenimentul (IP, tip,
  severitate), userul alege block / ignore / investigheaza mai departe
- logging complet pe orice actiune, automata sau manuala

## features suplimentare de diferentiere (toate in scope, roadmap)

- explicabilitate: nu doar scor de anomalie, ci motiv lizibil ("port
  neobisnuit pentru acest host + volum 5x peste medie")
- mod de simulare: buton care ruleaza un scenariu de atac controlat si
  safe (ex: port scan pe propriul VM), utilizatorul vede sistemul
  reactionand live - util si pentru demo
- cronologie/poveste a unui incident: gruparea evenimentelor individuale
  intr-o naratiune temporala per IP/sursa, nu doar lista plata
- prag de sensibilitate ajustabil vizual (slider) - control direct
  asupra ratei fals-pozitive/fals-negative
- raport exportabil (PDF/HTML) pentru o perioada data

## probleme cunoscute de anticipat

- rata mare de fals-pozitive - cea mai mare problema practica la orice
  NIDS, scan legitim arata identic cu atac
- trafic criptat (HTTPS/TLS) - nu poti inspecta payload, doar metadate
  (dimensiune, timing, destinatie) - ML pe metadate devine relevant aici
- volum mare de trafic -> risc de pierdere pachete daca procesarea nu
  tine pasul
- concept drift - comportamentul "normal" al retelei se schimba in timp,
  modelul local trebuie reantrenat periodic
- feature extraction gresit - features irelevante fac modelul ML inutil
  indiferent de algoritm
- cold start pe modelul local - nu are date la inceput, are nevoie de o
  perioada de "learning mode" (doar colecteaza, nu marcheaza anomalii)
- calibrare - scorurile celor doua modele nu sunt pe aceeasi scala,
  trebuie normalizare inainte de combinat/comparat

## stack - decis

Python: scikit-learn (Isolation Forest, One-Class SVM, K-Means, Random
Forest - toate native, mult mai mature decat echivalentul ML.NET),
Scapy pentru captura/parsare pachete. decizie luata deliberat ca sa
extinda orizontul dincolo de C#/.NET (folosit deja la teza de licenta,
Wifi Signal Optimizer).

UI: PySide6 (aplicatie desktop nativa, licenta LGPL - gratuita fara
restrictii, spre deosebire de PyQt). lansabila direct din VS Code.
prioritate: interfata profesionala si complexa, dar usor de inteles -
tab-uri/sectiuni clare, nu un singur ecran aglomerat. grafice live cu
pyqtgraph (mai rapid pentru date care se actualizeaza constant) sau
matplotlib pentru rapoarte statice.

## resurse necesare

totul ruleaza local, fara cloud, fara costuri. modelele alese sunt
usoare, ruleaza pe CPU. dataset-uri publice (NSL-KDD sub 50MB, CICIDS2017
cateva GB in functie de subset) sunt gratuite pentru uz educational.

## conventii de stil - la fel ca la celalalt proiect

- comentarii scurte, la obiect, fara diacritice, fara fraze de tip
  "folosim X" - stil student, nu manual corporate
- README/NOTES la fel, fara diacritice
- fisiere complete, nu diff-uri partiale
- fara nicio referinta explicita in cod/README la scopul de candidatura
  (relevant pentru profil SIE, dar repo-ul ramane un proiect tehnic
  neutru daca devine public)

## status curent

concept, arhitectura si stack complet stabilite (Python: scikit-learn +
Scapy + PySide6). niciun cod scris inca. urmatorul pas: structura de
proiect si feature extraction (identificat ca cea mai mare provocare
tehnica).
