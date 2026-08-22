# tabel port -> nume serviciu, aproximare bazata pe portul standard IANA.
# nu incearca sa reproduca exact vocabularul NSL-KDD (ex: "domain_u" pentru
# DNS peste UDP, "private" pentru porturi efemere) - scop practic: un
# nume de serviciu util pentru modelul propriu, nu compatibilitate stricta

_TCP_SERVICES = {
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    119: "nntp",
    143: "imap4",
    194: "irc",
    443: "http_443",
    445: "microsoft_ds",
    993: "imap4_ssl",
    995: "pop3_ssl",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
}

_UDP_SERVICES = {
    53: "domain_u",
    67: "dhcp",
    68: "dhcp",
    69: "tftp_u",
    123: "ntp_u",
    161: "snmp",
    500: "isakmp",
}


def service_name(protocol: str, port: int | None) -> str:
    if port is None:
        return "other"

    table = _TCP_SERVICES if protocol == "tcp" else _UDP_SERVICES if protocol == "udp" else {}
    if port in table:
        return table[port]

    return "private" if port >= 49152 else "other"
