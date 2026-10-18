"""Evidence-based device-type identification (camera, plug/bulb, TV, speaker, robot vacuum,
printer, NAS, ...).

Every signal names its source, and confidence comes from how much *independent* evidence agrees.
One weak signal (an OUI, or a single generic port) never gives more than "low". You get "high"
only when two or more independent sources agree, or one source is close to conclusive
(e.g. mDNS ``_ipp``, an RTSP port, a robot-vacuum vendor's cloud domain).

Works on whatever evidence is available: LAN-scan facts (open ports, mDNS, SSDP, hostname, OUI)
and/or capture facts (the DNS names / SNI the device contacted and the destination ports).
"""

from __future__ import annotations

TYPES = ("camera", "plug/bulb", "tv", "speaker", "robot-vacuum", "printer", "nas",
         "phone/tablet", "computer", "hub/bridge")

LABELS = {
    "camera": "IP camera / video doorbell",
    "plug/bulb": "Smart plug / bulb / switch",
    "tv": "Smart TV / streaming device",
    "speaker": "Smart speaker / audio",
    "robot-vacuum": "Robot vacuum",
    "printer": "Network printer",
    "nas": "NAS / file server",
    "phone/tablet": "Phone / tablet",
    "computer": "Computer",
    "hub/bridge": "Smart-home hub / bridge",
}

# weight: 3 = close to conclusive, 2 = strong, 1 = weak hint.

# Open TCP ports observed ON the device (LAN scan / nmap).
PORT_SIGNALS: dict[int, list[tuple[str, int]]] = {
    554: [("camera", 3)], 8554: [("camera", 2)], 8899: [("camera", 2)],
    37777: [("camera", 3)], 34567: [("camera", 2)],
    631: [("printer", 3)], 9100: [("printer", 3)], 515: [("printer", 2)],
    8008: [("tv", 2)], 8009: [("tv", 3)], 8001: [("tv", 2)], 9197: [("tv", 2)],
    7000: [("speaker", 2), ("tv", 1)], 7001: [("speaker", 1)],
    5000: [("nas", 2)], 5001: [("nas", 2)], 445: [("nas", 2), ("computer", 1)],
    139: [("nas", 1), ("computer", 1)], 548: [("nas", 2)], 2049: [("nas", 2)],
    111: [("nas", 1)],
    54321: [("plug/bulb", 1), ("robot-vacuum", 1)],
    6668: [("plug/bulb", 1)],
    62078: [("phone/tablet", 3)],
}

# Destination ports the device CONNECTED OUT to during a capture (weaker than listening ports).
DEST_PORT_SIGNALS: dict[int, list[tuple[str, int]]] = {
    8883: [],  # MQTT-over-TLS is generic IoT; no single type
    1883: [],
}

# mDNS service key (without leading underscore) -> type.
MDNS_SIGNALS: dict[str, list[tuple[str, int]]] = {
    "ipp": [("printer", 3)], "printer": [("printer", 3)], "pdl-datastream": [("printer", 3)],
    "scanner": [("printer", 2)], "uscan": [("printer", 2)], "uscans": [("printer", 2)],
    "googlecast": [("tv", 2), ("speaker", 1)], "androidtvremote2": [("tv", 3)],
    "airplay": [("tv", 1), ("speaker", 1)], "raop": [("speaker", 3)],
    "spotify-connect": [("speaker", 3)], "sonos": [("speaker", 3)],
    "smb": [("nas", 2)], "afpovertcp": [("nas", 3)], "adisk": [("nas", 2)],
    "nfs": [("nas", 2)], "ssh": [("computer", 1)], "sftp-ssh": [("computer", 1)],
    "hap": [("hub/bridge", 1)], "homekit": [("hub/bridge", 1)],
    "hue": [("hub/bridge", 3)], "matter": [("hub/bridge", 2)], "matterc": [("hub/bridge", 2)],
    "miio": [("plug/bulb", 1), ("robot-vacuum", 1)],
    "axis-video": [("camera", 3)], "rtsp": [("camera", 3)], "dahua": [("camera", 3)],
}

# Substring in a DNS name / TLS SNI the device talked to -> type. Lowercased match.
DOMAIN_SIGNALS: list[tuple[str, str, int]] = [
    # cameras / doorbells
    ("dahua", "camera", 3), ("hikvision", "camera", 3), ("hik-connect", "camera", 3),
    ("ezvizlife", "camera", 3), ("ezviz", "camera", 3), ("wyze", "camera", 3),
    ("ring.com", "camera", 3), ("blinkforhome", "camera", 3), ("eufylife", "camera", 2),
    ("reolink", "camera", 3), ("amcrest", "camera", 3), ("tplinkcloud", "plug/bulb", 1),
    ("ipcam", "camera", 2), ("nest.com", "camera", 2),
    # robot vacuums
    ("roborock", "robot-vacuum", 3), ("irobot", "robot-vacuum", 3), ("neato", "robot-vacuum", 3),
    ("ecovacs", "robot-vacuum", 3), ("roidmi", "robot-vacuum", 2), ("dreame", "robot-vacuum", 2),
    ("viomi", "robot-vacuum", 2),
    # TVs / streamers
    ("samsungcloudsolution", "tv", 2), ("samsungotn", "tv", 2), ("samsungtv", "tv", 3),
    ("lgtvsdp", "tv", 3), ("lgtvcommon", "tv", 3), ("lgsmartplatform", "tv", 2),
    ("roku.com", "tv", 3), ("rokutime", "tv", 3), ("vizio", "tv", 3),
    ("tcljd", "tv", 2), ("whaleycloud", "tv", 2), ("tdatemilk", "tv", 2),
    ("netflix", "tv", 1), ("hulu", "tv", 1),
    # speakers
    ("sonos.com", "speaker", 3), ("spotify", "speaker", 1), ("echo.amazon", "speaker", 2),
    ("alexa", "speaker", 2), ("sonos", "speaker", 2), ("bose", "speaker", 2),
    # printers
    ("hpeprint", "printer", 3), ("hpconnected", "printer", 3), ("eprintcenter", "printer", 3),
    ("brother.com", "printer", 2), ("epsonconnect", "printer", 3), (" cano", "printer", 1),
    ("printer", "printer", 1),
    # NAS
    ("synology", "nas", 3), ("quickconnect", "nas", 3), ("qnap", "nas", 3),
    ("myqnapcloud", "nas", 3), ("wd2go", "nas", 2), ("mycloud", "nas", 2),
    # plugs / bulbs / generic smart home clouds
    ("tuya", "plug/bulb", 1), ("iotbing", "plug/bulb", 1), ("tplinkra", "plug/bulb", 1),
    ("kasa", "plug/bulb", 2), ("meross", "plug/bulb", 2), ("gosund", "plug/bulb", 2),
    ("lifx", "plug/bulb", 3), ("yeelight", "plug/bulb", 2), ("wiz.connected", "plug/bulb", 3),
    ("shelly", "plug/bulb", 2), ("sonoff", "plug/bulb", 2), ("ewelink", "plug/bulb", 2),
    # hubs / bridges
    ("meethue", "hub/bridge", 3), ("hue.com", "hub/bridge", 2), ("smartthings", "hub/bridge", 2),
    ("home.nest", "hub/bridge", 1), ("aqara", "hub/bridge", 2), ("deconz", "hub/bridge", 2),
]

# OUI vendor substring -> type (always weak; vendor alone never asserts a product).
VENDOR_SIGNALS: list[tuple[str, str, int]] = [
    ("hangzhou hikvision", "camera", 2), ("dahua", "camera", 2), ("axis communications", "camera", 2),
    ("amcrest", "camera", 2), ("reolink", "camera", 2), ("wyze", "camera", 2),
    ("roborock", "robot-vacuum", 2), ("irobot", "robot-vacuum", 2), ("ecovacs", "robot-vacuum", 2),
    ("sonos", "speaker", 2), ("bose", "speaker", 2), ("sony", "tv", 1),
    ("roku", "tv", 2), ("vizio", "tv", 2), ("samsung", "tv", 1),
    ("hewlett packard", "printer", 1), ("hp inc", "printer", 1), ("brother", "printer", 1),
    ("seiko epson", "printer", 1), ("canon", "printer", 1),
    ("synology", "nas", 3), ("qnap", "nas", 3), ("western digital", "nas", 2),
    ("tp-link", "plug/bulb", 1), ("espressif", "plug/bulb", 1), ("tuya", "plug/bulb", 1),
    ("signify", "hub/bridge", 2), ("philips lighting", "hub/bridge", 2),
    ("apple", "phone/tablet", 1), ("google", "speaker", 1),
]

HOSTNAME_SIGNALS: list[tuple[str, str, int]] = [
    ("iphone", "phone/tablet", 3), ("ipad", "phone/tablet", 3), ("android", "phone/tablet", 2),
    ("macbook", "computer", 3), ("imac", "computer", 2), ("desktop-", "computer", 2),
    ("printer", "printer", 2), ("camera", "camera", 2), ("roborock", "robot-vacuum", 3),
    ("synology", "nas", 3), ("diskstation", "nas", 3), ("nas", "nas", 2),
    ("chromecast", "tv", 3), ("roku", "tv", 3), ("firetv", "tv", 3), ("appletv", "tv", 3),
    ("sonos", "speaker", 3), ("echo", "speaker", 2),
]


def _add(scores, sources, typ, weight, src):
    if weight <= 0:
        return
    scores[typ] = scores.get(typ, 0) + weight
    sources.setdefault(typ, set()).add(src)
    # a single strong signal is remembered so we can award "high" on its own
    if weight >= 3:
        sources.setdefault(typ, set()).add(f"{src}!strong")


def identify_device_type(
    open_ports=None,
    domains=None,
    mdns=None,
    vendor=None,
    hostname=None,
    dest_ports=None,
) -> dict:
    """Return {type, label, confidence, scores, evidence}. confidence in
    (high, medium, low, unknown). ``type`` is None when unknown."""
    scores: dict[str, int] = {}
    sources: dict[str, set] = {}
    evidence: list[str] = []

    for p in (open_ports or []):
        for typ, w in PORT_SIGNALS.get(p, []):
            _add(scores, sources, typ, w, "port")
            evidence.append(f"open port {p} -> {typ}")

    for p in (dest_ports or []):
        for typ, w in DEST_PORT_SIGNALS.get(p, []):
            _add(scores, sources, typ, w, "dest-port")

    for svc in (mdns or []):
        key = str(svc).lstrip("_").split(".")[0].lower()
        for typ, w in MDNS_SIGNALS.get(key, []):
            _add(scores, sources, typ, w, "mdns")
            evidence.append(f"mDNS _{key} -> {typ}")

    dl = [str(d).lower() for d in (domains or [])]
    for needle, typ, w in DOMAIN_SIGNALS:
        n = needle.strip()
        if any(n in d for d in dl):
            _add(scores, sources, typ, w, "domain")
            evidence.append(f"domain ~{n} -> {typ}")

    if vendor:
        vl = vendor.lower()
        for needle, typ, w in VENDOR_SIGNALS:
            if needle in vl:
                _add(scores, sources, typ, w, "oui")
                evidence.append(f"OUI {vendor} -> {typ}")

    if hostname:
        hl = hostname.lower()
        for needle, typ, w in HOSTNAME_SIGNALS:
            if needle in hl:
                _add(scores, sources, typ, w, "hostname")
                evidence.append(f"hostname ~{needle} -> {typ}")

    if not scores:
        return {"type": None, "label": None, "confidence": "unknown",
                "scores": {}, "evidence": evidence}

    best = max(scores, key=lambda t: scores[t])
    srcs = sources.get(best, set())
    distinct = {s for s in srcs if not s.endswith("!strong")}
    has_strong = any(s.endswith("!strong") for s in srcs)

    if has_strong and len(distinct) >= 2:
        conf = "high"
    elif has_strong or len(distinct) >= 2:
        conf = "medium"
    else:
        conf = "low"
    # weak OUI/dest-port-only evidence stays low
    if distinct <= {"oui"} and not has_strong:
        conf = "low"

    return {"type": best, "label": LABELS.get(best, best), "confidence": conf,
            "scores": dict(sorted(scores.items(), key=lambda kv: -kv[1])),
            "evidence": evidence}


def type_from_report(device: dict) -> dict:
    """Infer device type from a serialized capture report (analyze.to_dict output)."""
    domains: list[str] = list(device.get("dns_queries") or [])
    dest_ports: set[int] = set()
    for d in device.get("destinations") or []:
        domains.extend(d.get("domains") or [])
        dest_ports.update(d.get("ports") or [])
    open_ports = [p.get("port") for p in (device.get("open_ports") or []) if p.get("port")]
    return identify_device_type(
        open_ports=open_ports,
        domains=domains,
        vendor=device.get("vendor"),
        dest_ports=dest_ports,
    )
