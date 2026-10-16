"""Offline enrichment: country (optional GeoLite2 .mmdb), organisation/vendor from domain,
MAC vendor (small built-in OUI table), tracker detection. No network calls, no telemetry."""

from __future__ import annotations

import os
import re

# Domain suffix -> organisation. Extend via profiles / PRs.
DOMAIN_ORGS = {
    "amazonaws.com": "Amazon AWS", "aws.amazon.com": "Amazon AWS",
    "cloudfront.net": "Amazon CloudFront",
    "googleapis.com": "Google", "google.com": "Google", "gstatic.com": "Google",
    "1e100.net": "Google", "azure.com": "Microsoft Azure", "microsoft.com": "Microsoft",
    "tuya.com": "Tuya", "tuyaeu.com": "Tuya", "tuyaus.com": "Tuya", "tuyacn.com": "Tuya",
    "aliyuncs.com": "Alibaba Cloud", "alibaba.com": "Alibaba", "xiaomi.com": "Xiaomi",
    "mi.com": "Xiaomi", "io.mi.com": "Xiaomi", "akamaiedge.net": "Akamai", "akamai.net": "Akamai",
    "cloudflare.com": "Cloudflare", "ntp.org": "NTP Pool", "apple.com": "Apple",
    "icloud.com": "Apple", "facebook.com": "Meta", "doubleclick.net": "Google Ads",
    "umeng.com": "Umeng (Alibaba analytics)", "bugly.qq.com": "Tencent Bugly", "qq.com": "Tencent",
}

TRACKERS = {
    "doubleclick.net", "google-analytics.com", "app-measurement.com", "umeng.com",
    "bugly.qq.com", "crashlytics.com", "branch.io", "adjust.com", "appsflyer.com",
    "graph.facebook.com", "segment.io", "mixpanel.com", "amplitude.com", "sentry.io",
}

OUI = {
    "d8:1f:12": "Tuya Smart", "10:d5:61": "Tuya Smart", "68:57:2d": "Tuya Smart",
    "50:ec:50": "Beijing Xiaomi", "64:90:c1": "Beijing Xiaomi", "78:11:dc": "Xiaomi",
    "24:0a:c4": "Espressif", "30:ae:a4": "Espressif", "84:f3:eb": "Espressif",
    "a4:cf:12": "Espressif", "ec:fa:bc": "Espressif", "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi", "f0:9f:c2": "Ubiquiti", "44:65:0d": "Amazon",
    "fc:65:de": "Amazon", "e8:ab:fa": "Shenzhen Reecam (cameras)", "9c:8e:cd": "Amcrest",
}

_MAC_SEP = re.compile(r"[:\-.]")


def normalize_mac(mac: str | None) -> str | None:
    """Return canonical aa:bb:cc:dd:ee:ff, or None if incomplete/invalid.
    Accepts macOS unpadded forms like '0:1a:2b:3:4:5' and hyphen/dot separators."""
    if not mac:
        return None
    raw = mac.strip().lower()
    if not raw or "incomplete" in raw or raw in ("(incomplete)", "none", "unknown"):
        return None
    parts = _MAC_SEP.split(raw)
    if len(parts) != 6:
        return None
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octets):
        return None
    return ":".join(f"{o:02x}" for o in octets)


def suffix_match(name: str, table) -> str | None:
    name = name.lower().rstrip(".")
    parts = name.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in table:
            return cand
    return None


def org_for(domains) -> str | None:
    for d in domains:
        k = suffix_match(d, DOMAIN_ORGS)
        if k:
            return DOMAIN_ORGS[k]
    return None


def is_tracker(domains) -> bool:
    return any(suffix_match(d, TRACKERS) for d in domains)



_oui_cache: dict[str, str] | None = None

# Substrings (case-insensitive) that often appear on IoT Wi-Fi / BLE modules.
IOT_HINTS = (
    "tuya", "espressif", "beken", "realtek", "rtl87", "xiaomi", "eshine",
    "hangzhou", "shenzhen", "bilian", "esp32", "nordic semiconductor",
    "silicon laboratories", "texas instruments", "mediatek", "newracom",
    "shanghai high-flying", "ai-thinker", "mxchip", "wuxi", "qingdao",
    "beijing xiaomi", "universial", "universal scientific", "azurewave",
    "murata", "sparkfun", "particle", "ublox", "u-blox", "quectel",
    "simcom", "fibocom", "meig", "longsung", "sdmc", "amcrest", "reecam",
    "hikvision", "dahua", "tp-link", "tplink", "wyze", "aqara", "shelly",
    "sonoff", "itead", "espress", "shanghai mxchip", "da xia long que",
)


def is_likely_iot(vendor: str | None) -> bool:
    if not vendor:
        return False
    v = vendor.lower()
    return any(h in v for h in IOT_HINTS)


def _load_oui() -> dict[str, str]:
    """Load bundled IEEE MA-L table (gzipped), falling back to the tiny built-in set."""
    cache = dict(OUI)
    try:
        import gzip
        from importlib import resources

        raw = (resources.files("iotaudit") / "data" / "oui.txt.gz").read_bytes()
        for line in gzip.decompress(raw).decode("utf-8", "replace").splitlines():
            if not line or "\t" not in line and "	" not in line:
                continue
            prefix, _, org = line.partition("	")
            if len(prefix) == 8 and org:
                cache[prefix] = org
    except (FileNotFoundError, OSError, ModuleNotFoundError):
        pass
    path = os.environ.get("IOTAUDIT_OUI")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "(hex)" in line:
                    hexp, _, org = line.partition("(hex)")
                    key = normalize_mac(hexp.strip() + ":00:00:00")
                    if key:
                        cache[key[:8]] = org.strip()
    return cache


def mac_vendor(mac: str | None) -> str | None:
    global _oui_cache
    norm = normalize_mac(mac)
    if not norm:
        return None
    # Locally Administered Address bit => typically phone/laptop randomized MAC
    if int(norm[0:2], 16) & 0x02:
        return "random (phone/laptop)"
    if _oui_cache is None:
        _oui_cache = _load_oui()
    return _oui_cache.get(norm[:8])



def _bundled_mmdb() -> str | None:
    try:
        from importlib import resources
        p = resources.files("iotaudit") / "data" / "dbip-country-lite.mmdb"
        return str(p) if p.is_file() else None
    except (FileNotFoundError, ModuleNotFoundError, TypeError, AttributeError):
        return None


class Geo:
    """Country lookup. Uses --geoip / IOTAUDIT_GEOIP, else the bundled DB-IP Lite country DB."""

    def __init__(self, path: str | None = None):
        self.reader = None
        path = path or os.environ.get("IOTAUDIT_GEOIP") or _bundled_mmdb()
        if path and os.path.exists(path):
            try:
                import maxminddb
                self.reader = maxminddb.open_database(path)
            except Exception:  # noqa: BLE001 — missing maxminddb or bad file
                try:
                    # DB-IP / MaxMind readers via maxminddb only; soft-fail
                    self.reader = None
                except Exception:  # noqa: BLE001
                    self.reader = None

    def country(self, ip: str) -> str | None:
        if not self.reader:
            return None
        try:
            rec = self.reader.get(ip) or {}
        except Exception:  # noqa: BLE001
            return None
        if isinstance(rec, str):  # some DB-IP country DBs return bare ISO code
            return rec
        c = rec.get("country") or rec.get("registered_country") or {}
        if isinstance(c, dict):
            return c.get("iso_code") or c.get("names", {}).get("en")
        return None


_asn_rows: list[tuple[int, int, int, str]] | None = None


def _load_asn():
    global _asn_rows
    if _asn_rows is not None:
        return _asn_rows
    import gzip
    import ipaddress
    from importlib import resources
    rows: list[tuple[int, int, int, str]] = []
    try:
        raw = (resources.files("iotaudit") / "data" / "ip2asn-lite.tsv.gz").read_bytes()
        for line in gzip.decompress(raw).decode().splitlines():
            start, end, asn, org = line.split("	", 3)
            rows.append((int(ipaddress.ip_address(start)), int(ipaddress.ip_address(end)),
                         int(asn), org))
        rows.sort()
    except Exception:  # noqa: BLE001
        rows = []
    _asn_rows = rows
    return rows


def asn_org(ip: str) -> tuple[int | None, str | None]:
    """Return (asn, org) from the bundled ip2asn-lite table (cloud/IoT ASNs)."""
    import bisect
    import ipaddress
    try:
        n = int(ipaddress.ip_address(ip))
    except ValueError:
        return None, None
    rows = _load_asn()
    if not rows:
        return None, None
    starts = [r[0] for r in rows]
    i = bisect.bisect_right(starts, n) - 1
    if i >= 0 and rows[i][0] <= n <= rows[i][1]:
        return rows[i][2], rows[i][3]
    # linear fallback near ends
    for start, end, asn, org in rows:
        if start <= n <= end:
            return asn, org
    return None, None


# Well-known destination ports -> protocol label
PORT_LABELS = {
    8883: "MQTT-over-TLS",
    1883: "MQTT",
    443: "HTTPS",
    80: "HTTP",
    853: "DNS-over-TLS",
    993: "IMAPS",
    123: "NTP",
    53: "DNS",
    6668: "Tuya-LAN",
    8053: "Xiaomi-miIO",
}
