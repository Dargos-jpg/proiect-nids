import os

# BUG DE MEDIU gasit rulant suita completa (nu un bug de cod propriu):
# python -m pytest crapa intermitent cu segfault, mereu in interiorul
# backend-ului de threading al joblib (folosit de RandomForestClassifier/
# IsolationForest cu n_jobs=-1 la predict/fit) - trace-ul arata sute de
# thread-uri worker acumulate (Thread-500+) pana la crash. reprodus
# constant pe suita completa, dar NICIODATA pe fisiere individuale de test
# rulate izolat - semn ca e o problema de ACUMULARE peste multe
# antrenari/predictii RandomForest facute in aceeasi rulare pytest, nu un
# bug intr-un test anume. probabil o incompatibilitate intre backend-ul de
# threading al joblib si acest build de Python (3.14, foarte recent) pe
# Windows.
#
# fix: limitam explicit paralelismul joblib la 1 pentru intreaga sesiune
# de teste - codul de PRODUCTIE (scripturile de antrenare, retrain.py)
# ramane neschimbat, foloseste in continuare n_jobs=-1 pentru viteza reala;
# doar suita de teste (unde modelele sunt oricum jucarie, cateva randuri)
# forteaza executie seriala, eliminand cu totul crearea/distrugerea
# repetata de thread-pool-uri
os.environ.setdefault("LOKY_MAX_CPU_COUNT", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")
