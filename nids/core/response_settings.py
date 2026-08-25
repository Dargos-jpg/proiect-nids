from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ResponseSettings:
    """politica de raspuns automat - separata de MlSettings (nu e un
    parametru al modelelor, e o decizie de RASPUNS bazata pe iesirea lor).
    implicit dezactivata (opt-in) - blocarea, chiar temporara si
    reversibila (vezi BlockManager), e o actiune reala, nu ceva ce ar
    trebui sa se intample surprinzator din prima pornire a aplicatiei.

    citita live, nu doar la pornirea monitorizarii (spre deosebire de
    MlSettings/pragul de port scan) - poate fi pornita/oprita in mijlocul
    unei sesiuni deja active, fara sa fie nevoie de restart"""

    auto_block_enabled: bool = False
