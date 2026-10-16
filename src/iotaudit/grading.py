"""A-F grading and plain-English summary. Findings are indicators, not proof."""

from __future__ import annotations

from .enrich import PUBLIC_DNS, is_cgnat

PENALTY = {"high": 25, "medium": 10, "low": 4, "info": 0}
# Telnet is especially bad — already high (25); keep explicit weight note in finding.
GRADES = [(90, "A"), (75, "B"), (60, "C"), (45, "D"), (30, "E"), (0, "F")]

CATEGORY_BY_TITLE = {
    "Unencrypted": "encryption",
    "Non-standard encryption": "encryption",
    "Tracker": "tracker",
    "Destination": "destination",
    "Outdated TLS": "encryption",
    "Open port": "port",
    "Data sent": "destination",
    "Hardcoded": "dns",
    "STUN": "traffic-class",
    "Cloud servers": "location",
    "LAN peer": "traffic-class",
    "MQTT cloud": "destination",
    "Limited": "coverage",
}


def _normalize(x: dict) -> dict:
    x.setdefault("confidence", "certain")
    if "category" not in x:
        x["category"] = next(
            (c for k, c in CATEGORY_BY_TITLE.items() if x["title"].startswith(k)), "other"
        )
    return x


def findings_for(device) -> list[dict]:
    f: list[dict] = []
    dests = list(device.destinations.values())
    named = sum(1 for d in dests if d.domains)
    if dests and named == 0:
        f.append({
            "severity": "info",
            "title": "Limited visibility (no DNS/SNI seen)",
            "detail": "Only IP destinations were observed. Grade reflects limited data, "
                      "not a clean bill of health. Capture longer or trigger the app once.",
            "category": "coverage", "confidence": "certain",
        })
    hint = getattr(device, "_soft_hint", None)
    if hint:
        f.append({
            "severity": "info", "title": hint[0],
            "detail": "Inferred only from MQTT-over-TLS to a cloud ASN with no DNS/SNI. "
                      "Not a confirmed vendor match.",
            "category": "destination", "confidence": hint[1],
        })
    if not dests and not device.open_ports and not device.lan_peers:
        f.append({
            "severity": "info", "title": "Limited data — almost no traffic",
            "detail": "Very little was observed. Do not treat the grade as conclusive.",
            "category": "coverage", "confidence": "certain",
        })

    for d in dests:
        label = ", ".join(sorted(d.domains)) or d.ip
        if d.encryption_kind == "plaintext":
            # DNS to public resolvers is expected plaintext — covered by the DNS finding
            if d.ports <= {53} or d.ip in PUBLIC_DNS and d.ports <= {53}:
                pass
            else:
                frac = d.readable_fraction
                frac_s = f" (~{frac:.0%} readable)" if frac is not None else ""
                f.append({
                    "severity": "high",
                    "title": "Unencrypted traffic to the internet",
                    "detail": f"Plaintext traffic to {label} (ports {sorted(d.ports)}){frac_s}. "
                              f"{d.encryption_detail or ''}",
                })
        elif d.encryption_kind == "stun":
            # Already covered by STUN/TURN finding; do not call it plaintext
            pass
        elif d.encryption_kind == "custom-encryption":
            f.append({
                "severity": "medium",
                "title": "Non-standard encryption (custom protocol), unverified",
                "detail": f"Traffic to {label} (ports {sorted(d.ports)}) looks encrypted by entropy "
                          f"but is not TLS. {d.encryption_detail or ''}",
                "confidence": "medium",
            })
        if d.tracker:
            f.append({
                "severity": "medium", "title": "Tracker / analytics endpoint",
                "detail": f"Contacts {label}, listed as a tracker/analytics service.",
            })
        if d.expected is False:
            f.append({
                "severity": "low", "title": "Destination not in device profile",
                "detail": f"{label} is not an expected destination for {device.profile}.",
            })
        if 3478 in d.ports or "STUN/TURN" in d.protocols:
            f.append({
                "severity": "info",
                "title": "STUN/TURN (P2P video setup)",
                "detail": f"STUN/TURN to {label} ({d.org or d.ip}) — typical for peer-to-peer "
                          "video/audio; the media may stay on the LAN or go via a relay.",
                "category": "traffic-class", "confidence": "high",
            })
        if is_cgnat(d.ip) or "CGNAT-peer" in d.protocols:
            f.append({
                "severity": "info",
                "title": "Carrier NAT / P2P peer (100.64/10)",
                "detail": f"Traffic to {d.ip} is in CGNAT space — often a phone or peer behind "
                          "carrier-grade NAT during P2P video.",
                "category": "traffic-class", "confidence": "medium",
            })
        if d.ip in PUBLIC_DNS or (53 in d.ports and d.ip in PUBLIC_DNS):
            f.append({
                "severity": "medium",
                "title": "Hardcoded public DNS (bypasses router)",
                "detail": f"Device sent DNS to {d.ip}, bypassing your router's DNS. "
                          "Queries may leave your network even if you run Pi-hole.",
                "category": "dns", "confidence": "certain",
            })
        tc = d.traffic_class
        if tc and tc.label in ("video", "audio", "audio+video") and tc.confidence in ("medium", "high"):
            detail = d.__dict__.get("_tc_detail") or tc.label
            f.append({
                "severity": "info",
                "title": f"Traffic looks like {tc.label}",
                "detail": detail,
                "category": "traffic-class", "confidence": tc.confidence,
            })
        elif tc and tc.label == "p2p-setup":
            # STUN-only — do not claim media
            pass

    # Hardcoded DNS also via destination list even if org enrichment named it
    for d in dests:
        if d.ip in PUBLIC_DNS and not any(x["title"].startswith("Hardcoded") for x in f):
            f.append({
                "severity": "medium",
                "title": "Hardcoded public DNS (bypasses router)",
                "detail": f"Device sent DNS to {d.ip}.",
                "category": "dns", "confidence": "certain",
            })

    for flow_note in getattr(device, "_old_tls", []):
        f.append({"severity": "medium", "title": "Outdated TLS", "detail": flow_note})

    for p in device.open_ports:
        if p.get("risk"):
            f.append({
                "severity": p["risk"],
                "title": f"Open port {p['port']}/{p['proto']} ({p.get('service') or '?'})",
                "detail": p.get("why", ""),
            })

    countries = {d.country for d in dests if d.country}
    if countries:
        f.append({
            "severity": "info",
            "title": "Cloud servers outside the local network",
            "detail": "Observed destination countries: " + ", ".join(sorted(countries))
                      + ". This is a location note about servers the device contacted, "
                        "not a judgement about where you live.",
            "category": "location", "confidence": "certain",
        })

    lan_bytes = sum(d.bytes_out + d.bytes_in for d in device.lan_peers.values())
    if lan_bytes:
        peer_bits = []
        for ip, d in list(device.lan_peers.items())[:6]:
            tag = d.__dict__.get("looks_like") or ip
            peer_bits.append(f"{tag} ({d.bytes_out}B out / {d.bytes_in}B in)")
        f.append({
            "severity": "info",
            "title": "LAN peer traffic (device ↔ phone/PC on your Wi-Fi)",
            "detail": f"{lan_bytes} bytes unicast on LAN: " + "; ".join(peer_bits) + ". "
                      "Live video often stays here via P2P rather than as cloud upload. "
                      "Broadcasts (e.g. Tuya :6667) are listed separately.",
            "category": "traffic-class", "confidence": "certain",
        })
    if getattr(device, "broadcasts", None):
        total = sum(b.get("bytes_out", 0) for b in device.broadcasts)
        f.append({
            "severity": "info",
            "title": "LAN discovery broadcasts",
            "detail": f"{total} bytes of broadcast/multicast (e.g. Tuya UDP 6667) — not media.",
            "category": "traffic-class", "confidence": "certain",
        })

    # Deduplicate similar titles (keep first)
    seen = set()
    out = []
    for x in f:
        key = (x["title"], x.get("detail", "")[:40])
        if key in seen:
            continue
        seen.add(key)
        out.append(_normalize(x))
    return out


def grade(findings: list[dict]) -> tuple[int, str]:
    score = 100
    for x in findings:
        score -= PENALTY.get(x["severity"], 0)
    limited = any(x.get("category") == "coverage" for x in findings)
    if limited:
        score = min(score, 70)
    score = max(score, 0)
    letter = next(g for t, g in GRADES if score >= t)
    if limited and letter == "A":
        letter = "C"
    return score, letter


def summarize(device) -> str:
    """One plain-English paragraph for the top of the report."""
    bits = []
    who = device.profile or device.vendor or device.ip
    bits.append(f"Device {device.ip}" + (f" ({who})" if who != device.ip else "") + ".")
    if device.grade:
        bits.append(f"Grade {device.grade} ({device.score}/100).")
    dests = list(device.destinations.values())
    clouds = sorted({d.org for d in dests if d.org})
    if clouds:
        bits.append("Talked to: " + ", ".join(clouds[:6]) + ".")
    countries = sorted({d.country for d in dests if d.country})
    if countries:
        bits.append("Server countries observed: " + ", ".join(countries) + ".")
    if any(p.get("port") == 23 for p in device.open_ports):
        bits.append("Telnet (port 23) is open on the LAN — change defaults / block it.")
    if any(d.ip in PUBLIC_DNS for d in dests):
        bits.append("Uses public DNS directly (bypasses your router).")
    if any(3478 in d.ports for d in dests):
        bits.append("Used STUN/TURN (typical for P2P video setup).")
    lan = sum(d.bytes_out for d in device.lan_peers.values())
    wan = sum(d.bytes_out for d in dests)
    if lan:
        bits.append(f"LAN peer traffic {lan} bytes vs internet {wan} bytes "
                    "(video may have stayed on Wi-Fi).")
    if device.idle_upload:
        bits.append(f"Uploads while app idle: {device.idle_upload}.")
    if device.bursts:
        active = sum(1 for b in device.bursts if b["kind"] == "active")
        bits.append(f"Traffic pattern: {active} active burst(s) detected.")
    customs = [d for d in dests if d.encryption_kind == "custom-encryption"]
    if customs:
        bits.append(
            f"{len(customs)} destination(s) look like custom/non-TLS encryption (unverified)."
        )
    return " ".join(bits)
