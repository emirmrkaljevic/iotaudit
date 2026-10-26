"""Offline known-issue hints from banners iotaudit already observed.

The catalog is a small YAML file shipped in the package. Matching never
opens a socket and never downloads a feed.

Grade rule: a hint changes the score only when the observed version string
equals a version the entry lists exactly and the entry severity is critical.
That case subtracts 25 points (the same weight as one high finding), applied
after the limited-data cap. A version range, a product name without that
exact version, an open service alone, or any other severity leaves the score
unchanged. See ``affects_grade``.
"""

from __future__ import annotations

import re
from importlib import resources
from urllib.parse import urlsplit

import yaml

VERIFY_PHRASE = "possible, based on version string; verify firmware"
_SEVERITIES = ("low", "medium", "high", "critical")
_SEVERITY_RANK = {name: i for i, name in enumerate(reversed(_SEVERITIES))}
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_VERSION_RE = re.compile(r"\d+(?:\.\d+){0,3}")
_DASH_CODES = (0x2014, 0x2013)

# Product token -> version pattern in a banner or Server header.
_PRODUCT_VERSION = (
    ("dropbear", re.compile(r"dropbear[^0-9]{0,24}v?(\d{4}\.\d+)", re.I)),
    ("lighttpd", re.compile(r"lighttpd[^0-9]{0,8}v?(\d+\.\d+\.\d+)", re.I)),
    ("miniupnpd", re.compile(r"miniupnpd[^0-9]{0,8}v?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("busybox", re.compile(r"busybox[^0-9]{0,24}v?(\d+\.\d+\.\d+)", re.I)),
    ("rompager", re.compile(r"rompager[^0-9]{0,8}v?(\d+\.\d+)", re.I)),
    ("goahead", re.compile(r"goahead[^0-9]{0,12}v?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("live555", re.compile(r"live555[^0-9]{0,32}(\d{4}\.\d{2}\.\d{2}|\d+\.\d+)", re.I)),
    ("netkit", re.compile(r"netkit[^0-9]{0,16}v?(\d+\.\d+(?:\.\d+)?)", re.I)),
)

_CATALOG: list[dict] | None = None


def affects_grade(hint: dict) -> bool:
    """True only for an exact version match on a critical catalog entry."""
    return bool(hint.get("match_exact")) and hint.get("severity") == "critical"


def load_catalog() -> list[dict]:
    """Return the shipped catalog. Reads the package file once."""
    global _CATALOG
    if _CATALOG is None:
        path = resources.files("iotaudit").joinpath("data/known_issues.yaml")
        _CATALOG = _parse_catalog(path.read_text(encoding="utf-8"))
    return _CATALOG


def banner_from_payload(payload: bytes, sport: int, dport: int, proto: str) -> dict | None:
    """Pull a Server, SSDP, or RTSP auth fact out of a payload already captured.

    Returns None when the bytes are not one of those banners. Does no I/O.
    """
    if not payload:
        return None
    blob = payload[:2048]
    if proto == "udp" and (sport == 1900 or dport == 1900):
        return _ssdp_banner(blob, sport, dport)
    if proto == "tcp" and blob.startswith(b"RTSP/1."):
        return _rtsp_banner(blob, sport)
    if proto == "tcp" and blob.startswith(b"HTTP/1."):
        return _http_banner(blob, sport)
    return None


def hints_for_device(device, upnp: dict | None = None, entries: list[dict] | None = None) -> list[dict]:
    """Match one device. ``entries`` overrides the shipped catalog (tests)."""
    catalog = entries if entries is not None else load_catalog()
    return match_observations(_observations(device, upnp), catalog)


def match_observations(observations: list[dict], entries: list[dict]) -> list[dict]:
    hints = []
    for entry in entries:
        best = None
        for obs in observations:
            hit = _match_one(entry, obs)
            if hit is None:
                continue
            if best is None or (hit["match_exact"] and not best["match_exact"]):
                best = hit
        if best is not None:
            hints.append(best)
    hints.sort(key=lambda h: (-_SEVERITY_RANK.get(h["severity"], 0), h["cve"], h["id"]))
    return hints


def _parse_catalog(text: str) -> list[dict]:
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise ValueError("known_issues.yaml must contain an entries list")
    entries = []
    seen = set()
    for raw in data["entries"]:
        entry = _validate_entry(raw)
        if entry["id"] in seen or entry["cve"] in seen:
            raise ValueError(f"duplicate known-issue id or cve: {entry['id']}")
        seen.add(entry["id"])
        seen.add(entry["cve"])
        entries.append(entry)
    if not 10 <= len(entries) <= 20:
        raise ValueError(f"known-issue catalog must hold 10 to 20 entries, found {len(entries)}")
    return entries


def _validate_entry(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("known-issue entry must be a mapping")
    cve = str(raw.get("cve") or "")
    if not _CVE_RE.match(cve):
        raise ValueError(f"known-issue entry has no CVE id: {raw.get('id')}")
    severity = str(raw.get("severity") or "")
    if severity not in _SEVERITIES:
        raise ValueError(f"{cve} severity must be one of {', '.join(_SEVERITIES)}")
    reference = str(raw.get("reference") or "")
    expected = f"https://nvd.nist.gov/vuln/detail/{cve}"
    if reference != expected:
        raise ValueError(f"{cve} reference must be {expected}")
    summary = " ".join(str(raw.get("summary") or "").split())
    title = " ".join(str(raw.get("title") or "").split())
    if not summary or not title:
        raise ValueError(f"{cve} needs a title and a summary")
    for label, value in (("title", title), ("summary", summary)):
        if any(ord(ch) in _DASH_CODES for ch in value):
            raise ValueError(f"{cve} {label} contains a dash character")
    match = raw.get("match")
    if not isinstance(match, dict):
        raise ValueError(f"{cve} needs a match mapping")
    if not match.get("products") and not match.get("device_types"):
        raise ValueError(f"{cve} match needs products or device_types")
    return {
        "id": str(raw.get("id") or cve.lower()),
        "cve": cve,
        "severity": severity,
        "title": title,
        "summary": summary,
        "reference": reference,
        "match": match,
    }


def _observations(device, upnp: dict | None) -> list[dict]:
    out = []
    ports = _get(device, "open_ports") or []
    for port in ports:
        if isinstance(port, dict):
            out.append(_from_port(port))
    for note in _get(device, "service_banners") or []:
        if isinstance(note, dict):
            out.append(note)
    ip = str(_get(device, "ip") or "")
    for router in (upnp or {}).get("routers") or []:
        if not router.get("igd"):
            continue
        host = urlsplit(str(router.get("location") or "")).hostname or ""
        if host and host == ip:
            out.append({
                "source": "upnp",
                "service": "upnp",
                "port": None,
                "product": "",
                "version": "",
                "banner": str(router.get("server") or ""),
                "server": str(router.get("server") or ""),
                "device_type": "InternetGatewayDevice",
                "unauthenticated": None,
                "text": "InternetGatewayDevice " + str(router.get("server") or ""),
            })
    return out


def _from_port(port: dict) -> dict:
    product = str(port.get("product_name") or port.get("product") or "")
    version = str(port.get("version") or "")
    extra = str(port.get("extrainfo") or "")
    banner = str(port.get("banner") or "")
    server = str(port.get("server") or "")
    text = " ".join(x for x in (product, str(port.get("product") or ""), version, extra, banner, server) if x)
    unauth = port.get("unauthenticated")
    if unauth is None:
        unauth = _unauth_from_text(extra)
    service = str(port.get("service") or "") or _service_for_port(port.get("port"))
    return {
        "source": "port-scan",
        "service": service.lower(),
        "port": port.get("port"),
        "product": product,
        "version": version,
        "banner": banner or extra,
        "server": server,
        "device_type": str(port.get("device_type") or ""),
        "unauthenticated": unauth,
        "text": text,
    }


def _http_banner(payload: bytes, sport: int) -> dict | None:
    headers = _headers(payload)
    server = headers.get("server", "")
    if not server:
        return None
    return _note("http", "http", sport or None, server, server, None, "")


def _rtsp_banner(payload: bytes, sport: int) -> dict | None:
    headers = _headers(payload)
    first = payload.split(b"\r\n", 1)[0]
    if b" 401 " in first or "www-authenticate" in headers:
        unauth = False
    elif b" 200 " in first:
        unauth = True
    else:
        unauth = None
    server = headers.get("server", "")
    if unauth is None and not server:
        return None
    return _note("rtsp", "rtsp", sport or 554, server, server, unauth, "")


def _ssdp_banner(payload: bytes, sport: int, dport: int) -> dict | None:
    first = payload.split(b"\r\n", 1)[0]
    if first.startswith(b"M-SEARCH"):
        return None
    if not (first.startswith(b"NOTIFY ") or first.startswith(b"HTTP/1.")):
        return None
    headers = _headers(payload)
    server = headers.get("server", "")
    st = headers.get("st") or headers.get("nt") or ""
    device_type = st if "InternetGatewayDevice" in st else ""
    if not server and not device_type:
        return None
    return _note("ssdp", "upnp", 1900 if sport == 1900 or dport == 1900 else sport, server, server,
                 None, device_type)


def _note(source: str, service: str, port, server: str, product: str,
          unauth, device_type: str) -> dict:
    server = server[:200]
    product = product[:200]
    return {
        "source": source,
        "service": service,
        "port": port,
        "product": product,
        "version": "",
        "banner": server,
        "server": server,
        "device_type": device_type,
        "unauthenticated": unauth,
        "text": " ".join(x for x in (product, server, device_type) if x),
    }


def _headers(payload: bytes) -> dict[str, str]:
    headers = {}
    for line in payload.decode("utf-8", "replace").split("\r\n")[1:40]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()[:200]
    return headers


def _unauth_from_text(extra: str) -> bool | None:
    low = extra.lower()
    if any(phrase in low for phrase in ("unauthenticated", "no authentication", "no auth")):
        return True
    return None


def _service_for_port(port) -> str:
    return {
        21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 554: "rtsp",
        1900: "upnp", 5000: "upnp", 8080: "http", 8554: "rtsp",
    }.get(port, "")


def _match_one(entry: dict, obs: dict) -> dict | None:
    spec = entry["match"]
    products = [str(p).lower() for p in spec.get("products") or []]
    text = _obs_text(obs)
    if products and not any(_has_token(text, token) for token in products):
        return None
    types = [str(t).lower() for t in spec.get("device_types") or []]
    type_blob = (str(obs.get("device_type") or "") + " " + text).lower()
    if types and not any(token in type_blob for token in types):
        return None
    services = [str(s).lower() for s in spec.get("services") or []]
    if services and str(obs.get("service") or "").lower() not in services:
        return None
    ports = spec.get("ports") or []
    if ports and obs.get("port") not in ports:
        return None
    if spec.get("require_unauthenticated") and obs.get("unauthenticated") is not True:
        return None
    needs_version = any(key in spec for key in (
        "versions_exact", "version_below", "version_at_or_below", "version_at_or_above",
    ))
    version, is_exact = _version_match(spec, obs, products)
    if needs_version:
        if not version:
            return None
        if is_exact:
            matched_exact = True
        elif _in_range(spec, version):
            matched_exact = False
        else:
            return None
    else:
        # Service facts (for example an exposed IGD) are never an exact version match.
        matched_exact = False
        version = ""
    return _hint(entry, obs, version or "", matched_exact)


def _version_match(spec: dict, obs: dict, products: list[str]) -> tuple[str | None, bool]:
    observed = _observed_version(obs, products)
    if not observed:
        return None, False
    exact_list = [_normalize_version(v) for v in spec.get("versions_exact") or []]
    exact_list = [v for v in exact_list if v]
    return observed, observed in exact_list


def _in_range(spec: dict, version: str) -> bool:
    if "range_min_major" in spec:
        major = int(version.split(".", 1)[0])
        if major < int(spec["range_min_major"]):
            return False
    has_range = False
    if "version_below" in spec:
        has_range = True
        if _cmp(version, str(spec["version_below"])) >= 0:
            return False
    if "version_at_or_below" in spec:
        has_range = True
        if _cmp(version, str(spec["version_at_or_below"])) > 0:
            return False
    if "version_at_or_above" in spec:
        has_range = True
        if _cmp(version, str(spec["version_at_or_above"])) < 0:
            return False
    return has_range


def _observed_version(obs: dict, products: list[str]) -> str | None:
    explicit = _normalize_version(str(obs.get("version") or ""))
    if explicit:
        return explicit
    text = _obs_text(obs)
    found = {}
    for name, pattern in _PRODUCT_VERSION:
        match = pattern.search(text)
        if not match:
            continue
        norm = _normalize_version(match.group(1))
        if norm:
            found[name] = norm
    if products:
        for token in products:
            if token in found:
                return found[token]
    if len(found) == 1:
        return next(iter(found.values()))
    return None


def _hint(entry: dict, obs: dict, version: str, exact: bool) -> dict:
    summary = entry["summary"].rstrip(".")
    detail = f"{summary}. {VERIFY_PHRASE}."
    observed = _observed_text(obs, version)
    hint = {
        "id": entry["id"],
        "cve": entry["cve"],
        "severity": entry["severity"],
        "title": entry["title"],
        "detail": detail,
        "reference": entry["reference"],
        "observed": observed,
        "source": obs.get("source") or "",
        "match_exact": bool(exact),
        "affects_grade": False,
    }
    hint["affects_grade"] = affects_grade(hint)
    return hint


def _observed_text(obs: dict, version: str) -> str:
    bits = [str(obs.get("source") or "observed")]
    if obs.get("port"):
        bits.append(f"port {obs['port']}/{obs.get('service') or '?'}")
    elif obs.get("service"):
        bits.append(str(obs["service"]))
    product = str(obs.get("product") or obs.get("server") or "").strip()
    if product:
        bits.append(product[:120])
    if version:
        bits.append(f"version {version}")
    if obs.get("device_type"):
        bits.append(str(obs["device_type"])[:80])
    if obs.get("unauthenticated") is True:
        bits.append("RTSP or service did not ask for authentication")
    return " ".join(bits)


def _obs_text(obs: dict) -> str:
    parts = [
        obs.get("text"), obs.get("product"), obs.get("server"), obs.get("banner"),
        obs.get("version"), obs.get("device_type"),
    ]
    return " ".join(str(p) for p in parts if p).lower()


def _has_token(hay: str, needle: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", hay) is not None


def _normalize_version(raw: str) -> str | None:
    text = raw.strip()
    if len(text) > 1 and text[0] in "vV" and text[1].isdigit():
        text = text[1:]
    match = _VERSION_RE.fullmatch(text)
    if not match:
        return None
    return match.group(0)


def _cmp(left: str, right: str) -> int:
    aa = [int(part) for part in left.split(".")]
    bb = [int(part) for part in _normalize_version(right).split(".")] if _normalize_version(right) else []
    width = max(len(aa), len(bb))
    aa.extend([0] * (width - len(aa)))
    bb.extend([0] * (width - len(bb)))
    return (aa > bb) - (aa < bb)


def _get(device, key: str, default=None):
    if isinstance(device, dict):
        if key in device:
            return device[key]
        return device.get(key, default)
    if key == "service_banners":
        return getattr(device, "__dict__", {}).get("service_banners", default)
    return getattr(device, key, default)
