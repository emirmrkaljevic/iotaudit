"""Detect public DNS, DNS-over-TLS and DNS-over-HTTPS that bypass the router."""

from __future__ import annotations

from iotaudit.analyze import build_devices, to_dict
from iotaudit.capture import Collector
from iotaudit.enrich import is_doh_hostname, is_public_dns
from iotaudit.grading import findings_for, safety_verdict, summarize
from iotaudit.models import Destination, Device, Flow


def _titles(findings) -> list[str]:
    return [item["title"] for item in findings]


def test_public_dns_includes_ipv6_any_compression():
    assert is_public_dns("8.8.8.8")
    assert is_public_dns("2001:4860:4860::8888")
    assert is_public_dns("2001:4860:4860:0:0:0:0:8888")
    assert is_public_dns("2606:4700:4700::1111")
    assert not is_public_dns("1.2.3.4")
    assert not is_public_dns("192.168.0.1")


def test_doh_hostnames_match_suffixes():
    assert is_doh_hostname("dns.google")
    assert is_doh_hostname("cloudflare-dns.com")
    assert is_doh_hostname("mozilla.cloudflare-dns.com")
    assert is_doh_hostname("abcdef.dns.nextdns.io")
    assert is_doh_hostname("mask-h2.icloud.com")
    assert not is_doh_hostname("google.com")
    assert not is_doh_hostname("cloudflare.com")
    assert not is_doh_hostname("example.com")


def test_classic_public_dns_finding_and_verdict_still_work():
    col = Collector(["192.168.0.50"])
    flow = Flow("192.168.0.50", "8.8.8.8", 53, "udp", bytes=200, packets=4)
    col.flows[(flow.src, flow.dst, flow.dport, flow.proto)] = flow
    device = to_dict(build_devices(col)[0])
    assert any("Hardcoded public DNS" in title for title in _titles(device["findings"]))
    assert not any("DNS-over-HTTP" in title or "DNS-over-TLS" in title for title in _titles(device["findings"]))
    assert "uses public DNS directly" in device["verdict"]
    assert "DNS-over-HTTPS" not in device["verdict"]


def test_ipv6_public_dns_is_flagged():
    dest = Destination(ip="2001:4860:4860:0:0:0:0:8888", ports={53}, bytes_out=80)
    dev = Device(ip="192.168.0.50", grade="B", destinations={dest.ip: dest})
    titles = _titles(findings_for(dev))
    assert any("Hardcoded public DNS" in title for title in titles)
    assert "uses public DNS directly" in safety_verdict(dev)


def test_dns_over_tls_on_port_853():
    col = Collector(["192.168.0.50"])
    flow = Flow("192.168.0.50", "1.1.1.1", 853, "tcp", bytes=900, packets=8, tls=True)
    col.flows[(flow.src, flow.dst, flow.dport, flow.proto)] = flow
    built = build_devices(col)[0]
    device = to_dict(built)
    titles = _titles(device["findings"])
    assert any("DNS-over-TLS" in title for title in titles)
    assert not any("Hardcoded public DNS" in title for title in titles)
    assert "uses DNS-over-TLS" in device["verdict"]
    assert "encrypted cloud traffic" not in device["verdict"]
    dest = built.destinations["1.1.1.1"]
    assert "DNS-over-TLS" in dest.protocols


def test_dns_over_https_by_sni_is_certain():
    col = Collector(["192.168.0.50"])
    flow = Flow("192.168.0.50", "1.1.1.1", 443, "tcp", bytes=1500, packets=10, tls=True,
                sni="cloudflare-dns.com")
    col.flows[(flow.src, flow.dst, flow.dport, flow.proto)] = flow
    built = build_devices(col)[0]
    device = to_dict(built)
    finding = next(item for item in device["findings"] if "DNS-over-HTTPS" in item["title"])
    assert finding["confidence"] == "certain"
    assert "cloudflare-dns.com" in finding["detail"]
    assert "uses DNS-over-HTTPS" in device["verdict"]
    assert "encrypted cloud traffic" not in device["verdict"]
    assert "DNS-over-HTTPS" in built.destinations["1.1.1.1"].protocols
    assert "Uses DNS-over-HTTPS (bypasses your router)." in summarize(built)


def test_https_to_public_resolver_is_doh_with_high_confidence():
    dest = Destination(ip="8.8.8.8", ports={443}, encryption_kind="tls", bytes_out=1200)
    dev = Device(ip="192.168.0.50", grade="B", destinations={dest.ip: dest})
    findings = findings_for(dev)
    finding = next(item for item in findings if "DNS-over-HTTPS" in item["title"])
    assert finding["confidence"] == "high"
    assert not any("Hardcoded public DNS" in item["title"] for item in findings)
    text = safety_verdict(dev)
    assert "uses DNS-over-HTTPS" in text
    assert "encrypted cloud traffic" not in text


def test_https_to_an_ordinary_host_is_not_doh():
    dest = Destination(
        ip="203.0.113.10",
        ports={443},
        domains={"cdn.example.com"},
        encryption_kind="tls",
        bytes_out=50_000,
    )
    dev = Device(ip="192.168.0.50", grade="B", destinations={dest.ip: dest})
    titles = _titles(findings_for(dev))
    assert not any("DNS-over-HTTPS" in title or "DNS-over-TLS" in title or "Hardcoded public DNS" in title
                   for title in titles)
    assert "uses DNS-over-HTTPS" not in safety_verdict(dev)


def test_plain_dns_and_doh_can_both_appear():
    dev = Device(
        ip="192.168.0.50",
        grade="C",
        destinations={
            "8.8.8.8": Destination(ip="8.8.8.8", ports={53}, bytes_out=100),
            "1.1.1.1": Destination(
                ip="1.1.1.1",
                ports={443},
                domains={"cloudflare-dns.com"},
                encryption_kind="tls",
                bytes_out=800,
            ),
        },
    )
    titles = _titles(findings_for(dev))
    assert any("Hardcoded public DNS" in title for title in titles)
    assert any("DNS-over-HTTPS" in title for title in titles)
    text = safety_verdict(dev)
    assert "uses public DNS directly" in text
    assert "uses DNS-over-HTTPS" in text
