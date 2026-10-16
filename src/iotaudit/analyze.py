"""Turn captured flows into per-device findings and grades."""

from __future__ import annotations

from .capture import Collector
from .enrich import PORT_LABELS, Geo, asn_org, is_tracker, mac_vendor, org_for
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
        dest = devices.setdefault(f.src, Device(ip=f.src, mac=col.macs.get(f.src)))
        d = dest.destinations.setdefault(f.dst, Destination(ip=f.dst))
        d.ports.add(f.dport)
        d.bytes_out += f.bytes
        names = set(col.dns.get(f.dst, set()))
        if f.sni:
            names.add(f.sni.lower())
        if f.http_host:
            names.add(f.http_host.split(":")[0].lower())
        d.domains |= names
        if f.plaintext_http or (not f.tls and f.proto == "tcp" and f.dport not in ENCRYPTED_PORTS):
            d.encrypted = False
        if f.tls_version in ("TLS1.0", "TLS1.1"):
            dest.__dict__.setdefault("_old_tls", []).append(
                f"{f.tls_version} used to {f.sni or f.dst}.")
    for ip, qs in col.queries.items():
        if ip in devices:
            devices[ip].dns_queries |= qs
    for dest in devices.values():
        dest.vendor = mac_vendor(dest.mac)
        for d in dest.destinations.values():
            d.country = geo.country(d.ip)
            d.org = org_for(d.domains)
            if not d.org:
                _asn, org = asn_org(d.ip)
                if org:
                    d.org = org
            for port in d.ports:
                if port in PORT_LABELS:
                    d.protocols.add(PORT_LABELS[port])
            d.tracker = is_tracker(d.domains)
        prof = match_profile(dest, profiles)
        if not prof:
            # No DNS/SNI: Tuya feeders often only show MQTT-TLS :8883 to AWS
            ports = {p for d in dest.destinations.values() for p in d.ports}
            orgs = {d.org or "" for d in dest.destinations.values()}
            vendor = (dest.vendor or "").lower()
            tuya_oui = any(k in vendor for k in ("tuya", "espressif", "da xia long que", "bilian"))
            if 8883 in ports and (any(("Amazon" in o or "AWS" in o) for o in orgs) or tuya_oui):
                if tuya_oui:
                    prof = next((p for p in profiles if p.get("id") == "imipaw-pettech-feeder"), None)
                if not prof:
                    prof = next((p for p in profiles if p.get("id") == "tuya-generic"), None)
        dest.profile = prof.get("name") if prof else None
        for d in dest.destinations.values():
            d.expected = is_expected(d.domains, prof)
        if scans and dest.ip in scans:
            dest.open_ports = scans[dest.ip]
        dest.findings = findings_for(dest)
        dest.score, dest.grade = grade(dest.findings)
    return sorted(devices.values(), key=lambda d: d.ip)


def to_dict(dev: Device) -> dict:
    return {
        "ip": dev.ip, "mac": dev.mac, "vendor": dev.vendor, "profile": dev.profile,
        "grade": dev.grade, "score": dev.score, "findings": dev.findings,
        "open_ports": dev.open_ports, "dns_queries": sorted(dev.dns_queries),
        "destinations": [
            {"ip": d.ip, "domains": sorted(d.domains), "country": d.country, "org": d.org,
             "ports": sorted(d.ports), "bytes_out": d.bytes_out, "encrypted": d.encrypted,
             "tracker": d.tracker, "expected": d.expected, "protocols": sorted(d.protocols)}
            for d in sorted(dev.destinations.values(), key=lambda x: -x.bytes_out)
        ],
    }
