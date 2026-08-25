from __future__ import annotations

import subprocess

_RULE_PREFIX = "NIDS-block-"


def add_block_rule(ip: str) -> None:
    """adauga o regula de firewall Windows care blocheaza tot traficul
    de la acest IP. necesita drepturi de administrator - subprocess.run
    arunca CalledProcessError daca netsh refuza (ex: fara admin)"""
    subprocess.run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={_RULE_PREFIX}{ip}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
        ],
        check=True,
        capture_output=True,
    )


def remove_block_rule(ip: str) -> None:
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={_RULE_PREFIX}{ip}"],
        check=True,
        capture_output=True,
    )
