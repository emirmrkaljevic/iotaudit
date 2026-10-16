"""Turn captured flows into per-device findings and grades."""

from __future__ import annotations

from .capture import Collector
from .enrich import Geo, is_tracker, mac_vendor, org_for
from .grading import findings_for, grade
from .models import Destination, Device
from .profiles import is_expected, load_profiles, match_profile

ENCRYPTED_PORTS = {443, 8883, 853, 993, 995, 465, 5223, 8443, 6668, 8053}


def build_devices(col: Collector, geo: Geo | None = None, extra_profiles: str | None = None,
                  scans: dict[str, list] | None = None) -> list[Device]:
    geo = geo or Geo()
    profiles = load_profiles(extra_profiles)
    devices: dict[str, Device] = {}
    for f in col.flows.values():
        dev = devices.setdefault(f.src, Device(ip=f.src, mac=col.macs.get(f.src)))
        dest = dev.destinations.setdefault(f.dst, Destination(ip=f.dst))
        dest.ports.add(f.dport)
        dest.bytes_out += f.bytes
        names = set(col.dns.get(f.dst, set()))
        if f.sni:
            names.add(f.sni.lower())
        if f.http_host:
            names.add(f.http_host.split(":")[0].lower())
        dest.domains |= names
        if f.plaintext_http or (not f.tls and f.proto == "tcp" and f.dport not in ENCRYPTED_PORTS):
            dest.encrypted = False
        if f.tls_version in ("TLS1.0", "TLS1.1"):
            dev.__dict__.setdefault("_old_tls", []).append(
                f"{f.tls_version} used to {f.sni or f.dst}.")
    for ip, qs in col.queries.items():
        if ip in devices:
            devices[ip].dns_queries |= qs
    for dev in devices.values():
        dev.vendor = mac_vendor(dev.mac)
        prof = match_profile(dev, profiles)
        dev.profile = prof.get("name") if prof else None
        for d in dev.destinations.values():
            d.country = geo.country(d.ip)
            d.org = org_for(d.domains)
            d.tracker = is_tracker(d.domains)
            d.expected = is_expected(d.domains, prof)
        if scans and dev.ip in scans:
            dev.open_ports = scans[dev.ip]
        dev.findings = findings_for(dev)
        dev.score, dev.grade = grade(dev.findings)
    return sorted(devices.values(), key=lambda d: d.ip)


def to_dict(dev: Device) -> dict:
    return {
        "ip": dev.ip, "mac": dev.mac, "vendor": dev.vendor, "profile": dev.profile,
        "grade": dev.grade, "score": dev.score, "findings": dev.findings,
        "open_ports": dev.open_ports, "dns_queries": sorted(dev.dns_queries),
        "destinations": [
            {"ip": d.ip, "domains": sorted(d.domains), "country": d.country, "org": d.org,
             "ports": sorted(d.ports), "bytes_out": d.bytes_out, "encrypted": d.encrypted,
             "tracker": d.tracker, "expected": d.expected}
            for d in sorted(dev.destinations.values(), key=lambda x: -x.bytes_out)
        ],
    }
