"""Turn captured flows into per-device findings and grades."""

from __future__ import annotations

from .capture import Collector
from .enrich import (
    PORT_LABELS,
    Geo,
    asn_org,
    is_cgnat,
    is_special_use,
    is_tracker,
    mac_vendor,
    org_for,
    special_use_label,
)
from .grading import findings_for, grade, summarize
from .models import Destination, Device, TrafficClass
from .profiles import is_expected, load_profiles, match_profile
from .traffic import classify_traffic, detect_bursts, encryption_verdict, merge_series


def _apply_flow(d: Destination, f) -> None:
    d.ports.add(f.dport)
    d.bytes_out += f.bytes
    d.bytes_in += getattr(f, "bytes_in", 0) or 0
    d.packets += f.packets
    d.packets_in += getattr(f, "packets_in", 0) or 0
    d.lan = d.lan or f.lan
    if f.sni:
        d.domains.add(f.sni.lower())
    if f.http_host:
        d.domains.add(f.http_host.split(":")[0].lower())
    for k, v in (f.series or {}).items():
        d.series[k] = d.series.get(k, 0) + v
    if f.dport in PORT_LABELS:
        d.protocols.add(PORT_LABELS[f.dport])
    if f.dport == 3478:
        d.protocols.add("STUN/TURN")

    if f.tls or f.dport in (443, 8883, 853):
        ver = encryption_verdict(f.payload_samples, assumed_tls=True)
    elif f.plaintext_http:
        ver = {
            "kind": "plaintext",
            "confidence": "certain",
            "readable_fraction": 1.0,
            "detail": "HTTP plaintext observed.",
        }
    elif f.dport == 3478:
        ver = {
            "kind": "stun",
            "confidence": "certain",
            "readable_fraction": 0.0,
            "detail": "STUN/TURN signalling (not app-payload encryption).",
        }
    else:
        ver = encryption_verdict(f.payload_samples, assumed_tls=False)

    order = {"plaintext": 0, "unknown": 1, "custom-encryption": 2, "stun": 3, "tls": 4}
    prev = d.encryption_kind
    if prev is None or order.get(ver["kind"], 9) < order.get(prev, 9):
        d.encryption_kind = ver["kind"]
        d.encryption_detail = ver["detail"]
        d.readable_fraction = ver.get("readable_fraction")
    d.encrypted = d.encryption_kind != "plaintext"


def _enrich(d: Destination, geo: Geo, dns_map: dict) -> None:
    d.domains |= set(dns_map.get(d.ip, set()))
    d.country = geo.country(d.ip)
    d.org = org_for(d.domains)
    if not d.org:
        _asn, org = asn_org(d.ip)
        if org:
            d.org = org
    if is_cgnat(d.ip):
        d.org = d.org or "CGNAT / P2P peer"
        d.protocols.add("CGNAT-peer")
    if is_special_use(d.ip):
        d.__dict__["special_use"] = True
        d.org = d.org or "special-use / bogon"
        d.protocols.add("special-use")
        d.__dict__.setdefault("looks_like", special_use_label(d.ip))
    d.tracker = is_tracker(d.domains)
    if d.series:
        duration = max(d.series) - min(d.series) + 10
        avg_pkt = (d.bytes_out / d.packets) if d.packets else None
        tc = classify_traffic(d.bytes_out, duration, d.ports, avg_pkt, d.protocols)
        d.traffic_class = TrafficClass(
            label=tc["label"], confidence=tc["confidence"], evidence=tc.get("evidence") or {}
        )
        d.__dict__["_tc_detail"] = tc.get("detail")
        d.bursts = detect_bursts(d.series)



def _idle_upload_verdict(device: Device) -> str:
    """Compare low-activity baseline vs larger outbound bursts on internet destinations."""
    series = device.series_total or {}
    if len(series) < 3:
        return "insufficient data"
    rates = sorted(v * 8 / 10 for v in series.values())
    n = max(1, len(rates) // 5)
    baseline = sum(rates[:n]) / n
    threshold = max(baseline * 3, 50_000)
    spikes = [r for r in rates if r >= threshold]
    if not spikes:
        return "none detected"
    wan = sum(d.bytes_out for d in device.destinations.values())
    if wan < 100_000:
        return "none detected (bursts were small / likely signalling; check LAN peers for video)"
    return "detected"


def build_devices(
    col: Collector,
    geo: Geo | None = None,
    extra_profiles: str | None = None,
    scans: dict[str, list] | None = None,
    peer_labels: dict[str, str] | None = None,
) -> list[Device]:
    geo = geo or Geo()
    profiles = load_profiles(extra_profiles)
    devices: dict[str, Device] = {}

    def ensure(ip: str) -> Device:
        return devices.setdefault(ip, Device(ip=ip, mac=col.macs.get(ip)))

    from .capture import is_broadcast_or_multicast

    all_flows = list(col.flows.values()) + list(getattr(col, "lan_flows", {}).values())
    for f in all_flows:
        dest = ensure(f.src)
        if f.lan and is_broadcast_or_multicast(f.dst):
            # Discovery broadcasts (e.g. Tuya 255.255.255.255:6667) — not media peers
            b = next((x for x in dest.broadcasts if x.get("ip") == f.dst and x.get("port") == f.dport), None)
            if not b:
                b = {"ip": f.dst, "port": f.dport, "proto": f.proto, "bytes_out": 0, "packets": 0}
                dest.broadcasts.append(b)
            b["bytes_out"] += f.bytes
            b["packets"] += f.packets
            continue
        bucket = dest.lan_peers if f.lan else dest.destinations
        d = bucket.setdefault(f.dst, Destination(ip=f.dst, lan=f.lan))
        _apply_flow(d, f)

    for ip, qs in col.queries.items():
        if ip in devices:
            devices[ip].dns_queries |= qs

    for dest in devices.values():
        dest.vendor = mac_vendor(dest.mac)
        for d in list(dest.destinations.values()) + list(dest.lan_peers.values()):
            _enrich(d, geo, col.dns)
            for port in d.ports:
                if port in PORT_LABELS:
                    d.protocols.add(PORT_LABELS[port])

        prof = match_profile(dest, profiles)
        soft_hint = None
        cloud_dns = any("." in n and not n.endswith(".local") for n in dest.dns_queries) or any(
            d.domains for d in dest.destinations.values()
        )
        if not prof:
            ports = {p for d in dest.destinations.values() for p in d.ports}
            orgs = {d.org or "" for d in dest.destinations.values()}
            aws_mqtt = 8883 in ports and any(("Amazon" in o or "AWS" in o) for o in orgs)
            if aws_mqtt and not cloud_dns:
                soft_hint = (
                    "MQTT cloud device, possibly Tuya (AWS :8883, no DNS/SNI)",
                    "low",
                )
        dest.profile = prof.get("name") if prof else None
        if soft_hint and not dest.profile:
            dest.__dict__["_soft_hint"] = soft_hint
        for d in dest.destinations.values():
            d.expected = is_expected(d.domains, prof)
        if scans and dest.ip in scans:
            dest.open_ports = scans[dest.ip]
        if peer_labels:
            for ip, d in dest.lan_peers.items():
                if ip in peer_labels:
                    d.__dict__["looks_like"] = peer_labels[ip]

        dest.series_total = merge_series([d.series for d in dest.destinations.values()])
        dest.bursts = detect_bursts(dest.series_total)
        dest.idle_upload = _idle_upload_verdict(dest)
        try:
            dest.__dict__["ipv6"] = col.ipv6_summary(dest.mac)
        except Exception:  # noqa: BLE001
            dest.__dict__["ipv6"] = {}
        dest.findings = findings_for(dest)
        dest.score, dest.grade = grade(dest.findings)
        dest.summary = summarize(dest)

    return sorted(devices.values(), key=lambda d: d.ip)


def _dest_dict(d: Destination) -> dict:
    tc = None
    if d.traffic_class:
        tc = {
            "label": d.traffic_class.label,
            "confidence": d.traffic_class.confidence,
            "detail": d.__dict__.get("_tc_detail"),
            "evidence": d.traffic_class.evidence,
        }
    return {
        "ip": d.ip,
        "looks_like": d.__dict__.get("looks_like"),
        "domains": sorted(d.domains),
        "country": d.country,
        "org": d.org,
        "ports": sorted(d.ports),
        "bytes_out": d.bytes_out,
        "bytes_in": d.bytes_in,
        "packets": d.packets,
        "packets_in": d.packets_in,
        "encrypted": d.encrypted,
        "encryption_kind": d.encryption_kind,
        "encryption_detail": d.encryption_detail,
        "readable_fraction": d.readable_fraction,
        "tracker": d.tracker,
        "expected": d.expected,
        "protocols": sorted(d.protocols),
        "traffic_class": tc,
        "series": {str(k): v for k, v in sorted(d.series.items())},
        "bursts": d.bursts,
        "lan": d.lan,
        "special_use": bool(d.__dict__.get("special_use")),
    }


def to_dict(dev: Device) -> dict:
    return {
        "ip": dev.ip,
        "mac": dev.mac,
        "vendor": dev.vendor,
        "profile": dev.profile,
        "grade": dev.grade,
        "score": dev.score,
        "summary": dev.summary,
        "idle_upload": dev.idle_upload,
        "findings": dev.findings,
        "open_ports": dev.open_ports,
        "dns_queries": sorted(dev.dns_queries),
        "destinations": [
            _dest_dict(d)
            for d in sorted(dev.destinations.values(), key=lambda x: -x.bytes_out)
        ],
        "lan_peers": [
            _dest_dict(d)
            for d in sorted(dev.lan_peers.values(), key=lambda x: -x.bytes_out)
        ],
        "broadcasts": dev.broadcasts,
        "series_total": {str(k): v for k, v in sorted(dev.series_total.items())},
        "bursts": dev.bursts,
        "ipv6": dev.__dict__.get("ipv6", {}),
    }
