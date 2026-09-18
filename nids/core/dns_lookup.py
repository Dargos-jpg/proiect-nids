from __future__ import annotations

import socket
from dataclasses import dataclass

from scapy.all import DNS, DNSQR

DEFAULT_TIMEOUT_SECONDS = 2.0

_CYMRU_RESOLVER = "8.8.8.8"
_CYMRU_RESOLVER_PORT = 53


def reverse_dns_lookup(ip: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> str | None:
    """DNS invers (inregistrare PTR) - "cine e acest IP", nu scraping de
    date personale: aceeasi informatie standard de retea pe care ai avea-o
    din `nslookup`/`dig -x`, disponibila public pentru orice adresa cu o
    inregistrare PTR configurata. None daca nu exista PTR, IP-ul nu
    raspunde, sau lookup-ul depaseste timeout-ul.

    socket.gethostbyaddr() nu accepta timeout ca parametru - setam
    temporar timeout-ul implicit al modulului socket, apoi il restauram,
    ca sa nu afecteze alte conexiuni din aplicatie facute intre timp"""
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)


def reverse_dns_lookup_many(ips: list[str], timeout: float = DEFAULT_TIMEOUT_SECONDS) -> dict[str, str | None]:
    return {ip: reverse_dns_lookup(ip, timeout) for ip in ips}


@dataclass
class AsnInfo:
    """cine detine efectiv reteaua din care face parte un IP - vezi
    Team Cymru IP-to-ASN lookup (https://team-cymru.com/community-services/ip-asn-mapping/),
    disponibil ca inregistrari TXT publice, la fel de "publice" ca PTR-ul
    de mai sus, doar ca acopera si IP-uri fara PTR configurat (majoritatea
    IP-urilor rezidentiale/cloud) - vine direct din datele BGP anuntate pe
    internet, nu dintr-o configurare optionala facuta de proprietar"""

    asn: str
    bgp_prefix: str
    country: str
    registry: str
    organization: str


def _query_txt(qname: str, timeout: float) -> str | None:
    """interogare bruta DNS TXT peste un socket UDP normal (nu are nevoie
    de drepturi de Administrator/raw socket, spre deosebire de captura de
    pachete) - folosim scapy doar pentru encodare/decodare (deja o
    dependinta a proiectului, folosita si pentru parsarea pachetelor DNS
    capturate in nids/capture/dns_meta.py), catre un resolver public fix,
    la fel cum se recomanda in documentatia Team Cymru (`dig ... @8.8.8.8`)"""
    query = DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(bytes(query), (_CYMRU_RESOLVER, _CYMRU_RESOLVER_PORT))
        data, _ = sock.recvfrom(2048)
    except OSError:
        return None
    finally:
        sock.close()

    response = DNS(data)
    if response.ancount < 1:
        return None
    rdata = response.an.rdata
    if isinstance(rdata, (list, tuple)):
        rdata = b"".join(part.encode() if isinstance(part, str) else part for part in rdata)
    if isinstance(rdata, bytes):
        rdata = rdata.decode("utf-8", errors="replace")
    return rdata


def asn_lookup(ip: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> AsnInfo | None:
    """AS/organizatie/tara/prefix BGP pentru un IPv4, via Team Cymru.
    None pentru IPv6 (schema de interogare e diferita - nibble-uri hex,
    nu octeti - neimplementata deocamdata), sau daca oricare interogare
    DNS esueaza/depaseste timeout-ul.

    doua interogari TXT separate, in lant:
    1. "<ip invers>.origin.asn.cymru.com" -> ASN + prefixul BGP + tara + RIR
    2. "AS<asn>.asn.cymru.com" -> numele organizatiei pentru acel ASN
    (formatul exact al ambelor raspunsuri e documentat de Team Cymru)"""
    if ":" in ip:
        return None

    reversed_ip = ".".join(reversed(ip.split(".")))
    origin = _query_txt(f"{reversed_ip}.origin.asn.cymru.com", timeout)
    if origin is None:
        return None

    fields = [field.strip() for field in origin.split("|")]
    if len(fields) < 4:
        return None
    # un prefix poate fi anuntat de mai multe ASN-uri deodata (separate
    # prin spatiu in acelasi camp) - il luam pe primul, e suficient pentru
    # a identifica organizatia
    asn = fields[0].split()[0]
    bgp_prefix, country, registry = fields[1], fields[2], fields[3]

    organization = "necunoscuta"
    asn_name = _query_txt(f"AS{asn}.asn.cymru.com", timeout)
    if asn_name is not None:
        name_fields = [field.strip() for field in asn_name.split("|")]
        if len(name_fields) >= 5:
            organization = name_fields[4]

    return AsnInfo(
        asn=asn, bgp_prefix=bgp_prefix, country=country, registry=registry, organization=organization
    )


def asn_lookup_many(ips: list[str], timeout: float = DEFAULT_TIMEOUT_SECONDS) -> dict[str, AsnInfo | None]:
    return {ip: asn_lookup(ip, timeout) for ip in ips}


@dataclass
class IpLookupResult:
    hostname: str | None
    asn_info: AsnInfo | None


def lookup_ip_details(ip: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> IpLookupResult:
    return IpLookupResult(
        hostname=reverse_dns_lookup(ip, timeout),
        asn_info=asn_lookup(ip, timeout),
    )


def lookup_ip_details_many(
    ips: list[str], timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> dict[str, IpLookupResult]:
    return {ip: lookup_ip_details(ip, timeout) for ip in ips}
