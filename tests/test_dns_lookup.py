import socket

from nids.core import dns_lookup
from nids.core.dns_lookup import (
    AsnInfo,
    IpLookupResult,
    asn_lookup,
    asn_lookup_many,
    lookup_ip_details,
    lookup_ip_details_many,
    reverse_dns_lookup,
    reverse_dns_lookup_many,
)


def test_reverse_dns_lookup_returns_hostname(monkeypatch):
    monkeypatch.setattr(
        socket, "gethostbyaddr", lambda ip: ("example.com", [], ["1.2.3.4"])
    )

    assert reverse_dns_lookup("1.2.3.4") == "example.com"


def test_reverse_dns_lookup_returns_none_when_no_ptr_record(monkeypatch):
    def raise_herror(ip):
        raise socket.herror("unknown host")

    monkeypatch.setattr(socket, "gethostbyaddr", raise_herror)

    assert reverse_dns_lookup("1.2.3.4") is None


def test_reverse_dns_lookup_returns_none_on_timeout(monkeypatch):
    def raise_timeout(ip):
        raise socket.timeout("timed out")

    monkeypatch.setattr(socket, "gethostbyaddr", raise_timeout)

    assert reverse_dns_lookup("1.2.3.4") is None


def test_reverse_dns_lookup_restores_default_timeout(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("example.com", [], []))
    socket.setdefaulttimeout(None)

    reverse_dns_lookup("1.2.3.4", timeout=5.0)

    assert socket.getdefaulttimeout() is None


def test_reverse_dns_lookup_many_resolves_each_ip(monkeypatch):
    def fake_lookup(ip):
        if ip == "1.2.3.4":
            return ("known.example.com", [], [])
        raise socket.herror("unknown")

    monkeypatch.setattr(socket, "gethostbyaddr", fake_lookup)

    results = reverse_dns_lookup_many(["1.2.3.4", "5.6.7.8"])

    assert results == {"1.2.3.4": "known.example.com", "5.6.7.8": None}


# --- lookup AS/organizatie (Team Cymru) ---


def _fake_query_txt(origin_reply: str | None, asn_name_reply: str | None):
    def fake(qname: str, timeout: float) -> str | None:
        if qname.endswith(".origin.asn.cymru.com"):
            return origin_reply
        return asn_name_reply

    return fake


def test_asn_lookup_returns_parsed_info(monkeypatch):
    monkeypatch.setattr(
        dns_lookup,
        "_query_txt",
        _fake_query_txt(
            "15169 | 8.8.8.0/24 | US | arin | 2023-12-28",
            "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US",
        ),
    )

    info = asn_lookup("8.8.8.8")

    assert info == AsnInfo(
        asn="15169",
        bgp_prefix="8.8.8.0/24",
        country="US",
        registry="arin",
        organization="GOOGLE - Google LLC, US",
    )


def test_asn_lookup_returns_none_when_origin_query_fails(monkeypatch):
    monkeypatch.setattr(dns_lookup, "_query_txt", _fake_query_txt(None, "nu conteaza"))

    assert asn_lookup("8.8.8.8") is None


def test_asn_lookup_falls_back_to_unknown_organization_when_name_query_fails(monkeypatch):
    monkeypatch.setattr(
        dns_lookup,
        "_query_txt",
        _fake_query_txt("15169 | 8.8.8.0/24 | US | arin | 2023-12-28", None),
    )

    info = asn_lookup("8.8.8.8")

    assert info.organization == "necunoscuta"


def test_asn_lookup_returns_none_for_ipv6(monkeypatch):
    calls = []
    monkeypatch.setattr(dns_lookup, "_query_txt", lambda *a: calls.append(a))

    assert asn_lookup("::1") is None
    assert calls == []


def test_asn_lookup_many_resolves_each_ip(monkeypatch):
    monkeypatch.setattr(
        dns_lookup,
        "_query_txt",
        _fake_query_txt(
            "15169 | 8.8.8.0/24 | US | arin | 2023-12-28",
            "15169 | US | arin | 2000-03-30 | GOOGLE, US",
        ),
    )

    results = asn_lookup_many(["8.8.8.8", "8.8.4.4"])

    assert set(results) == {"8.8.8.8", "8.8.4.4"}
    assert all(info.asn == "15169" for info in results.values())


# --- lookup combinat (PTR + AS) ---


def test_lookup_ip_details_combines_hostname_and_asn_info(monkeypatch):
    monkeypatch.setattr(
        socket, "gethostbyaddr", lambda ip: ("dns.google", [], [ip])
    )
    monkeypatch.setattr(
        dns_lookup,
        "_query_txt",
        _fake_query_txt(
            "15169 | 8.8.8.0/24 | US | arin | 2023-12-28",
            "15169 | US | arin | 2000-03-30 | GOOGLE, US",
        ),
    )

    result = lookup_ip_details("8.8.8.8")

    assert result == IpLookupResult(
        hostname="dns.google",
        asn_info=AsnInfo(
            asn="15169", bgp_prefix="8.8.8.0/24", country="US", registry="arin", organization="GOOGLE, US"
        ),
    )


def test_lookup_ip_details_many_resolves_each_ip(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: (f"host-{ip}", [], [ip]))
    monkeypatch.setattr(dns_lookup, "_query_txt", _fake_query_txt(None, None))

    results = lookup_ip_details_many(["1.2.3.4", "5.6.7.8"])

    assert results["1.2.3.4"] == IpLookupResult(hostname="host-1.2.3.4", asn_info=None)
    assert results["5.6.7.8"] == IpLookupResult(hostname="host-5.6.7.8", asn_info=None)
