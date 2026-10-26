"""A-F grading, a one-line safety verdict, and a plain-English summary.

The verdict states observed facts plainly (open ports, public DNS, TLS versus
plaintext, destination countries). Traffic patterns stay indicators: a match
is never worded as proof, and nothing here accuses a vendor.
"""

from __future__ import annotations

from .enrich import PUBLIC_DNS, is_cgnat, is_special_use
from .hints import affects_grade
from .traffic import PATTERN_DISPLAY

PENALTY = {"high": 25, "medium": 10, "low": 4, "info": 0}
# Telnet is especially bad (already high, 25); keep an explicit weight note in the finding.
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
    "Traffic pattern": "traffic-class",
}

# Pattern inference is never an observed fact, so "certain" is not a valid rank here.
_CONF_RANK = {"low": 1, "medium": 2, "high": 3}


# p2p-setup stays in the summary block only. The STUN/TURN finding already covers it,
# and calling it media would overclaim.
_PATTERN_FINDING_LABELS = ("video", "audio", "audio+video", "telemetry", "unknown")


def destination_country_summary(destinations) -> tuple[list[dict], int]:
    """Group internet destinations by country.

    Country comes from a local lookup of an IP the device contacted, so each
    row is an observed fact (confidence "certain"). Destinations with no
    country are counted and not given a guessed country.
    """
    buckets: dict[str, dict] = {}
    unresolved = 0
    for d in destinations:
        country = getattr(d, "country", None)
        if not country:
            unresolved += 1
            continue
        row = buckets.get(country)
        if row is None:
            row = {
                "country": country,
                "destinations": 0,
                "bytes_out": 0,
                "bytes_in": 0,
                "orgs": [],
                "confidence": "certain",
                "kind": "observed",
            }
            buckets[country] = row
        row["destinations"] += 1
        row["bytes_out"] += int(getattr(d, "bytes_out", 0) or 0)
        row["bytes_in"] += int(getattr(d, "bytes_in", 0) or 0)
        org = getattr(d, "org", None)
        if org and org not in row["orgs"]:
            row["orgs"].append(org)
    rows = sorted(buckets.values(), key=lambda r: (-r["bytes_out"], r["country"]))
    for row in rows:
        row["orgs"] = sorted(row["orgs"])
    return rows, unresolved


def _tc_detail(dest) -> str | None:
    return dest.__dict__.get("_tc_detail") or None


def _pattern_sentence(label: str, where: str, count: int, confidence: str, mixed: bool) -> str:
    display = PATTERN_DISPLAY.get(label, label)
    conf = (
        f"Strongest confidence: {confidence}."
        if mixed
        else f"Confidence: {confidence}."
    )
    return (
        f"Pattern looks like {display} ({where}, {count} destination(s)). "
        f"{conf} Indicator only, not proof of what was sent."
    )


def traffic_pattern_summary(destinations, lan_peers=None) -> list[dict]:
    """Roll up inferred traffic classes for one device.

    Each row is an indicator (video, audio, telemetry, unknown, and so on)
    with low, medium, or high confidence. Special-use peers are skipped
    because they are not real devices on the Wi-Fi. Confidence is never
    "certain": a pattern match is not an observed fact.
    """
    groups: dict[tuple[str, str], dict] = {}

    def add(dest, where: str) -> None:
        if where == "lan" and (
            dest.__dict__.get("special_use") or is_special_use(getattr(dest, "ip", "") or "")
        ):
            return
        tc = getattr(dest, "traffic_class", None)
        label = getattr(tc, "label", None)
        if not label:
            return
        conf = getattr(tc, "confidence", None) or "low"
        # A pattern is an indicator. Never publish it as an observed fact.
        if conf == "certain":
            conf = "high"
        elif conf not in _CONF_RANK:
            conf = "low"
        key = (where, label)
        row = groups.get(key)
        if row is None:
            row = {
                "label": label,
                "display": PATTERN_DISPLAY.get(label, label),
                "where": where,
                "confidence": conf,
                "confidences": {conf},
                "destinations": 0,
                "bytes_out": 0,
                "bytes_in": 0,
                "details": [],
                "kind": "indicator",
            }
            groups[key] = row
        else:
            row["confidences"].add(conf)
            if _CONF_RANK[conf] > _CONF_RANK[row["confidence"]]:
                row["confidence"] = conf
        row["destinations"] += 1
        row["bytes_out"] += int(getattr(dest, "bytes_out", 0) or 0)
        row["bytes_in"] += int(getattr(dest, "bytes_in", 0) or 0)
        detail = _tc_detail(dest)
        if detail and detail not in row["details"] and len(row["details"]) < 2:
            row["details"].append(detail)

    for dest in destinations:
        add(dest, "internet")
    for dest in lan_peers or []:
        add(dest, "lan")

    out = []
    for row in groups.values():
        mixed = len(row.pop("confidences")) > 1
        row["summary"] = _pattern_sentence(
            row["label"], row["where"], row["destinations"], row["confidence"], mixed
        )
        out.append(row)
    out.sort(key=lambda r: (
        -_CONF_RANK.get(r["confidence"], 0), -r["bytes_out"], r["label"], r["where"]
    ))
    return out


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
            "severity": "info", "title": "Limited data, almost no traffic",
            "detail": "Very little was observed. Do not treat the grade as conclusive.",
            "category": "coverage", "confidence": "certain",
        })

    for d in dests:
        label = ", ".join(sorted(d.domains)) or d.ip
        if d.encryption_kind == "plaintext":
            # DNS to public resolvers is expected plaintext (covered by the DNS finding).
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
                "detail": f"STUN/TURN to {label} ({d.org or d.ip}), typical for peer-to-peer "
                          "video/audio. The media may stay on the LAN or go via a relay.",
                "category": "traffic-class", "confidence": "high",
            })
        if is_cgnat(d.ip) or "CGNAT-peer" in d.protocols:
            f.append({
                "severity": "info",
                "title": "Carrier NAT / P2P peer (100.64/10)",
                "detail": f"Traffic to {d.ip} is in CGNAT space, often a phone or peer behind "
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

    country_rows, unresolved_countries = destination_country_summary(dests)
    if country_rows:
        parts = [
            f"{c['country']} ({c['bytes_out']} bytes out, {c['destinations']} destination(s))"
            for c in country_rows
        ]
        detail = (
            "Observed destination countries: " + "; ".join(parts)
            + ". Country is a local lookup of an IP this device contacted "
            "(an observed fact), not a guess, and not a judgement about where you live."
        )
        if unresolved_countries:
            detail += f" {unresolved_countries} destination(s) had no country on file."
        f.append({
            "severity": "info",
            "title": "Cloud servers outside the local network",
            "detail": detail,
            "category": "location", "confidence": "certain",
            "evidence": {"countries": [c["country"] for c in country_rows]},
        })

    for pattern in traffic_pattern_summary(dests, list(device.lan_peers.values())):
        if pattern["label"] not in _PATTERN_FINDING_LABELS:
            continue
        detail = pattern["summary"]
        if pattern["details"]:
            detail += " " + pattern["details"][0]
        f.append({
            "severity": "info",
            "title": f"Traffic pattern looks like {pattern['display']} (indicator)",
            "detail": detail,
            "category": "traffic-class",
            "confidence": pattern["confidence"],
            "evidence": {
                "label": pattern["label"],
                "where": pattern["where"],
                "destinations": pattern["destinations"],
                "bytes_out": pattern["bytes_out"],
                "bytes_in": pattern["bytes_in"],
            },
        })

    real_peers = {ip: d for ip, d in device.lan_peers.items()
                  if not (d.__dict__.get("special_use") or is_special_use(ip))}
    special_peers = {ip: d for ip, d in device.lan_peers.items()
                     if d.__dict__.get("special_use") or is_special_use(ip)}
    real_lan_bytes = sum(d.bytes_out + d.bytes_in for d in real_peers.values())
    if real_lan_bytes:
        peer_bits = []
        for ip, d in list(real_peers.items())[:6]:
            tag = d.__dict__.get("looks_like") or ip
            peer_bits.append(f"{tag} ({d.bytes_out}B out / {d.bytes_in}B in)")
        f.append({
            "severity": "info",
            "title": "LAN peer traffic (device ↔ phone/PC on your Wi-Fi)",
            "detail": f"{real_lan_bytes} bytes unicast on LAN: " + "; ".join(peer_bits) + ". "
                      "Live video often stays here via P2P rather than as cloud upload. "
                      "Broadcasts (e.g. Tuya :6667) are listed separately.",
            "category": "traffic-class", "confidence": "certain",
        })
    if special_peers:
        bits = []
        for ip, d in list(special_peers.items())[:4]:
            bits.append(f"{ip} ({d.bytes_out + d.bytes_in}B)")
        f.append({
            "severity": "info",
            "title": "Odd \"LAN peer\" in special-use address space",
            "detail": "Saw traffic to/from " + ", ".join(bits) + ", which is reserved / "
                      "protocol-assignment space (e.g. 192.0.0.0/24), not a real device on your "
                      "Wi-Fi. It is almost always a placeholder/DS-Lite address or an address "
                      "carried inside P2P/STUN signalling, not a second hidden gadget.",
            "category": "traffic-class", "confidence": "high",
        })
    if getattr(device, "broadcasts", None):
        total = sum(b.get("bytes_out", 0) for b in device.broadcasts)
        f.append({
            "severity": "info",
            "title": "LAN discovery broadcasts",
            "detail": f"{total} bytes of broadcast/multicast (e.g. Tuya UDP 6667), not media.",
            "category": "traffic-class", "confidence": "certain",
        })

    # Honest note: STUN/P2P was set up but no media stream was actually captured here.
    stun_present = any((3478 in d.ports) or ("STUN/TURN" in d.protocols) for d in dests)
    observed_media = any(
        (d.traffic_class and d.traffic_class.label in ("video", "audio", "audio+video")
         and d.traffic_class.confidence in ("medium", "high"))
        for d in dests + list(device.lan_peers.values())
    )
    _real_lan_bytes = sum(
        d.bytes_out + d.bytes_in for ip, d in device.lan_peers.items()
        if not (d.__dict__.get("special_use") or is_special_use(ip))
    )
    ipv6 = getattr(device, "__dict__", {}).get("ipv6") or {}
    ipv6_ndp = sum((ipv6.get("ndp") or {}).values()) if isinstance(ipv6.get("ndp"), dict) else 0
    ipv6_media = ipv6.get("bytes", 0) or 0
    if stun_present and not observed_media and _real_lan_bytes < 500_000 and ipv6_media < 500_000:
        extra = ""
        if ipv6_ndp or ipv6.get("flows"):
            extra = (f" IPv6 was active (NDP messages: {ipv6_ndp}, "
                     f"IPv6 flows seen: {ipv6.get('flows', 0)}), so the stream may be riding "
                     "IPv6 link-local between the two devices.")
        f.append({
            "severity": "info",
            "title": "Live video set up but not observed here",
            "detail": "The device negotiated a peer-to-peer session (STUN/TURN) but no sustained "
                      "video/audio stream was captured on this run. It most likely went directly "
                      "between the device and your phone over Wi-Fi (P2P) and never passed through "
                      "this computer: two Wi-Fi clients can talk without their traffic crossing "
                      "your Mac, and spoofed ARP/NDP may not redirect it (client isolation, or the "
                      "phone ignoring the spoof)." + extra + " Not observed does not mean it did "
                      "not happen. Re-run with the app streaming, or capture at the router.",
            "category": "traffic-class", "confidence": "high",
        })
    # IPv6 coverage note (always, so the report is explicit about what it could see).
    if ipv6.get("any_ipv6_seen"):
        f.append({
            "severity": "info",
            "title": "IPv6 traffic observed",
            "detail": f"{ipv6.get('flows', 0)} IPv6 flow(s), {ipv6.get('bytes', 0)} bytes "
                      f"({ipv6.get('link_local_bytes', 0)} on link-local fe80::); "
                      f"NDP neighbor-discovery messages: {ipv6_ndp}. IPv6 enrichment "
                      "(country/org) is limited; link-local P2P between two Wi-Fi clients may not "
                      "be fully capturable without router-side capture.",
            "category": "traffic-class", "confidence": "certain",
        })
    elif isinstance(ipv6, dict) and "any_ipv6_seen" in ipv6 and stun_present:
        f.append({
            "severity": "info",
            "title": "No IPv6 traffic observed",
            "detail": "No IPv6 packets or NDP were seen from this device on this run. If live "
                      "video still was not captured, the stream likely stayed on IPv4 LAN P2P "
                      "(not redirected to us) rather than on IPv6.",
            "category": "traffic-class", "confidence": "medium",
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


def grade(findings: list[dict], hints: list[dict] | None = None) -> tuple[int, str]:
    """Score findings, then apply known-issue hints.

    A hint changes the score only when ``affects_grade`` is true: the observed
    version matched a catalog version exactly and the entry severity is
    critical. That case subtracts 25 points, the same as one high finding.
    The subtraction happens after the limited-data cap, so a critical exact
    hint still moves a thin capture. Every other hint is ignored here.
    """
    score = 100
    for x in findings:
        score -= PENALTY.get(x["severity"], 0)
    limited = any(x.get("category") == "coverage" for x in findings)
    if limited:
        score = min(score, 70)
    for hint in hints or []:
        if affects_grade(hint):
            score -= PENALTY["high"]
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
    dt = getattr(device, "__dict__", {}).get("device_type")
    if dt and dt.get("type") and dt.get("confidence") in ("high", "medium"):
        bits.append(f"Looks like a {dt['label']} ({dt['confidence']} confidence).")
    if device.grade:
        bits.append(f"Grade {device.grade} ({device.score}/100).")
    dests = list(device.destinations.values())
    clouds = sorted({d.org for d in dests if d.org})
    if clouds:
        bits.append("Talked to: " + ", ".join(clouds[:6]) + ".")
    country_rows, unresolved_countries = destination_country_summary(dests)
    if country_rows:
        bits.append(
            "Observed destination countries: "
            + ", ".join(f"{c['country']} ({c['bytes_out']} bytes out)" for c in country_rows)
            + "."
        )
    if unresolved_countries:
        bits.append(f"{unresolved_countries} internet destination(s) had no country on file.")
    patterns = traffic_pattern_summary(dests, list(device.lan_peers.values()))
    if patterns:
        bits.append(
            "Traffic pattern indicators (not proof): "
            + "; ".join(
                f"looks like {p['display']} on {p['where']} (confidence {p['confidence']})"
                for p in patterns
            )
            + "."
        )
    if any(p.get("port") == 23 for p in device.open_ports):
        bits.append("Telnet (port 23) is open on the LAN. Change defaults or block it.")
    if any(d.ip in PUBLIC_DNS for d in dests):
        bits.append("Uses public DNS directly (bypasses your router).")
    if any(3478 in d.ports for d in dests):
        bits.append("Used STUN/TURN (typical for P2P video setup).")
    lan = sum(d.bytes_out for ip, d in device.lan_peers.items()
              if not (d.__dict__.get("special_use") or is_special_use(ip)))
    wan = sum(d.bytes_out for d in dests)
    if lan:
        bits.append(f"LAN peer traffic {lan} bytes vs internet {wan} bytes "
                    "(video may have stayed on Wi-Fi).")
    elif any(3478 in d.ports for d in dests):
        bits.append("A P2P video session was set up but no media stream was captured here. "
                    "It likely went straight to your phone over Wi-Fi (not observed).")
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


# Short names for risky LAN services. The port number is what was observed.
_PORT_LABELS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    554: "RTSP",
    1900: "UPnP",
    5000: "UPnP",
    5555: "ADB",
    6668: "Tuya local",
    8080: "HTTP",
    8899: "ONVIF",
}

_MEDIA_LABELS = ("video", "audio", "audio+video")
# Same bar as the "stream not observed" finding: below this we do not call it media.
_MEDIA_BYTES = 500_000


def _port_label(port: dict) -> str:
    num = port.get("port")
    if num in _PORT_LABELS:
        return _PORT_LABELS[num]
    service = (port.get("service") or "").strip()
    if service and service.lower() not in {"unknown", "tcpwrapped", "?"}:
        return service[:1].upper() + service[1:]
    return f"Port {num}"


def _ports_clause(labels: list[str]) -> str:
    if len(labels) == 1:
        return f"{labels[0]} open on the LAN"
    if len(labels) == 2:
        return f"{labels[0]} and {labels[1]} open on the LAN"
    return ", ".join(labels[:-1]) + f", and {labels[-1]} open on the LAN"


def _dns_only(dest) -> bool:
    """DNS itself is not cloud-app traffic. Public resolvers get their own fact."""
    ports = set(getattr(dest, "ports", None) or ())
    if not ports:
        return getattr(dest, "ip", None) in PUBLIC_DNS
    return ports <= {53}


def _country_label(rows: list[dict]) -> str | None:
    if not rows:
        return None
    names = [row["country"] for row in rows[:3]]
    label = ", ".join(names)
    extra = len(rows) - len(names)
    if extra:
        label = f"{label}, +{extra}"
    return label


def _with_place(phrase: str, place: str | None) -> str:
    if place:
        return f"{phrase} ({place})"
    return phrase


def _encryption_clauses(cloud: list, place: str | None) -> list[str]:
    """TLS versus plaintext is an observed fact. Custom encryption is unverified."""
    kinds = {getattr(d, "encryption_kind", None) for d in cloud}
    has_plain = "plaintext" in kinds
    has_tls = "tls" in kinds
    has_custom = "custom-encryption" in kinds
    clauses: list[str] = []
    if has_plain and has_tls:
        clauses.append(_with_place("plaintext and TLS cloud traffic", place))
    elif has_plain:
        clauses.append(_with_place("plaintext traffic to the internet", place))
    elif has_tls and not has_custom:
        clauses.append(_with_place("encrypted cloud traffic", place))
    elif has_tls:
        clauses.append(_with_place("TLS cloud traffic", place))
    elif has_custom:
        if place:
            clauses.append(f"custom encryption to the cloud ({place}, unverified)")
        else:
            clauses.append("custom encryption to the cloud (unverified)")
        return clauses
    elif cloud:
        if place:
            clauses.append(f"cloud traffic ({place}), encryption not confirmed")
        else:
            clauses.append("cloud traffic, encryption not confirmed")
        return clauses
    if has_custom:
        clauses.append("custom encryption (unverified)")
    return clauses


def _real_lan_bytes(device) -> int:
    total = 0
    for ip, dest in device.lan_peers.items():
        if dest.__dict__.get("special_use") or is_special_use(ip):
            continue
        total += int(dest.bytes_out or 0) + int(dest.bytes_in or 0)
    return total


def _ipv6_bytes(device) -> int:
    ipv6 = device.__dict__.get("ipv6") or {}
    if not isinstance(ipv6, dict):
        return 0
    return int(ipv6.get("bytes") or 0)


def _strongest_media_confidence(device, dests) -> str | None:
    """Medium or high media patterns only. Low is not enough to say a stream was seen."""
    best = None
    for dest in list(dests) + list(device.lan_peers.values()):
        if dest.__dict__.get("special_use") or is_special_use(getattr(dest, "ip", "") or ""):
            continue
        tc = getattr(dest, "traffic_class", None)
        label = getattr(tc, "label", None)
        if label not in _MEDIA_LABELS:
            continue
        conf = getattr(tc, "confidence", None) or "low"
        if conf == "certain":
            conf = "high"
        elif conf not in _CONF_RANK:
            conf = "low"
        if conf not in ("medium", "high"):
            continue
        if best is None or _CONF_RANK[conf] > _CONF_RANK[best]:
            best = conf
    return best


def _pattern_indicator(device, dests) -> str | None:
    """One hedged pattern clause. Confidence is never 'certain'."""
    patterns = traffic_pattern_summary(dests, list(device.lan_peers.values()))
    if not patterns:
        return None
    pattern = patterns[0]
    return f"looks like {pattern['display']} (confidence {pattern['confidence']})"


def _indicator_clause(device, dests) -> str | None:
    """Traffic-pattern indicator. Never a claim that media contents were proven."""
    stun = any(
        3478 in (getattr(d, "ports", None) or ())
        or "STUN/TURN" in (getattr(d, "protocols", None) or ())
        for d in dests
    )
    media_conf = _strongest_media_confidence(device, dests)
    lan_bytes = _real_lan_bytes(device)
    ipv6_bytes = _ipv6_bytes(device)
    if stun and media_conf:
        return f"P2P video setup (looks like a stream, confidence {media_conf})"
    if stun and (lan_bytes >= _MEDIA_BYTES or ipv6_bytes >= _MEDIA_BYTES):
        return "P2P video setup (traffic seen, stream not confirmed)"
    if stun:
        # STUN/TURN was observed. A media stream was not. "Video" is the usual
        # role of that handshake, not a claim we saw one.
        return "P2P video setup (stream not observed here)"
    return _pattern_indicator(device, dests)


def _letter(device) -> str:
    letter = getattr(device, "grade", None)
    if letter in set("ABCDEF"):
        return letter
    _, letter = grade(
        list(getattr(device, "findings", None) or []),
        list(getattr(device, "known_issue_hints", None) or []),
    )
    return letter


def safety_verdict(device) -> str:
    """One skimmable line: grade, observed facts, then at most one hedged indicator.

    Example: "D: Telnet open on the LAN; uses public DNS directly; encrypted
    cloud traffic (US); P2P video setup (stream not observed here)."
    """
    dests = list(device.destinations.values())
    facts: list[str] = []

    risky: list[str] = []
    for port in device.open_ports or []:
        if not port.get("risk"):
            continue
        label = _port_label(port)
        if label not in risky:
            risky.append(label)
    if risky:
        facts.append(_ports_clause(risky))
    elif device.open_ports:
        facts.append("no risky ports")

    if any(d.ip in PUBLIC_DNS for d in dests):
        facts.append("uses public DNS directly")

    cloud = [d for d in dests if not _dns_only(d)]
    country_rows, _unresolved = destination_country_summary(dests)
    place = _country_label(country_rows)
    if cloud:
        facts.extend(_encryption_clauses(cloud, place))
    elif place:
        facts.append(f"servers in {place}")

    trackers = sum(1 for d in dests if getattr(d, "tracker", False))
    if trackers == 1:
        facts.append("one analytics tracker")
    elif trackers > 1:
        facts.append(f"{trackers} analytics trackers")

    parts = list(facts)
    indicator = _indicator_clause(device, dests)
    if indicator:
        parts.append(indicator)
    if not parts:
        parts.append("little traffic observed, so this grade is not conclusive")

    body = "; ".join(parts)
    if not body.endswith("."):
        body += "."
    return f"{_letter(device)}: {body}"
