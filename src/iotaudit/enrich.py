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
    "iotbing.com": "iotbing (Tuya-associated cloud)",
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
            except Exception:  # noqa: BLE001  missing maxminddb or bad file
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
    3478: "STUN/TURN",
    5349: "STUN/TURN-TLS",
    554: "RTSP",
    8554: "RTSP",
    1443: "custom-1443",
}

# Well-known public resolvers. Devices that send DNS (or DoT/DoH) here bypass
# the router resolver and any local filter such as Pi-hole.
PUBLIC_DNS = {
    # Google Public DNS
    "8.8.8.8", "8.8.4.4",
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    # Cloudflare
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2606:4700:4700::1112", "2606:4700:4700::1002",
    "2606:4700:4700::1113", "2606:4700:4700::1003",
    # Quad9
    "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10",
    "2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10",
    # Cisco OpenDNS
    "208.67.222.222", "208.67.220.220",
    "2620:119:35::35", "2620:119:53::53",
    # AdGuard DNS
    "94.140.14.14", "94.140.15.15",
    "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
}

# Hostnames used for DNS-over-HTTPS (and often DNS-over-TLS). Match exact or
# as a suffix (foo.dns.google, dns.nextdns.io, instance.nextdns.io).
DOH_HOST_SUFFIXES = (
    "dns.google",
    "dns.google.com",
    "cloudflare-dns.com",
    "one.one.one.one",
    "dns.quad9.net",
    "dns.adguard.com",
    "dns.adguard-dns.com",
    "doh.opendns.com",
    "family.opendns.com",
    "nextdns.io",
    "dns.sb",
    "doh.dns.sb",
    "cleanbrowsing.org",
    "dns.mullvad.net",
    "mask.icloud.com",
    "mask-h2.icloud.com",
    "dns.alidns.com",
    "doh.pub",
    "dns.controld.com",
)

_DNS_PORTS = {53, 443, 853}


def canon_ip(ip: str) -> str:
    """Compressed, lowercase IP form, or the original string if it is not an IP."""
    import ipaddress
    try:
        return format(ipaddress.ip_address(ip))
    except ValueError:
        return ip


_PUBLIC_DNS_CANON = {canon_ip(ip) for ip in PUBLIC_DNS}


def is_public_dns(ip: str | None) -> bool:
    """True if ip is a well-known public resolver (IPv4 or IPv6, any compression)."""
    if not ip:
        return False
    return canon_ip(ip) in _PUBLIC_DNS_CANON


def is_doh_hostname(name: str | None) -> bool:
    if not name:
        return False
    host = name.lower().rstrip(".")
    return any(host == suffix or host.endswith("." + suffix) for suffix in DOH_HOST_SUFFIXES)


def dest_names(dest) -> set[str]:
    return {n.lower().rstrip(".") for n in (getattr(dest, "domains", None) or set()) if n}


def dest_doh_names(dest) -> list[str]:
    return sorted(n for n in dest_names(dest) if is_doh_hostname(n))


def dest_uses_classic_dns(dest) -> bool:
    """Plain DNS (port 53) to a public resolver, or a public-resolver IP with no ports yet."""
    if not is_public_dns(getattr(dest, "ip", None)):
        return False
    ports = set(getattr(dest, "ports", None) or ())
    return (not ports) or (53 in ports)


def dest_uses_dot(dest) -> bool:
    """DNS-over-TLS: destination port 853, which is assigned to DoT."""
    ports = set(getattr(dest, "ports", None) or ())
    return 853 in ports


def dest_uses_doh(dest) -> bool:
    """DNS-over-HTTPS: a known DoH hostname, or HTTPS to a known public resolver IP."""
    if dest_doh_names(dest):
        return True
    ports = set(getattr(dest, "ports", None) or ())
    return 443 in ports and is_public_dns(getattr(dest, "ip", None))


def dest_doh_certain(dest) -> bool:
    return bool(dest_doh_names(dest))


def dest_is_dns_bypass(dest) -> bool:
    return dest_uses_classic_dns(dest) or dest_uses_dot(dest) or dest_uses_doh(dest)


def dest_is_dns_only(dest) -> bool:
    """Traffic that is only DNS (plain, DoT, or DoH), not a cloud app."""
    ports = set(getattr(dest, "ports", None) or ())
    if dest_uses_dot(dest) or dest_uses_doh(dest) or dest_uses_classic_dns(dest):
        return (not ports) or ports <= _DNS_PORTS
    return False


def tag_encrypted_dns(dest) -> None:
    """Add protocol labels once destinations have ports and domains."""
    protocols = getattr(dest, "protocols", None)
    if protocols is None:
        return
    if dest_uses_dot(dest):
        protocols.add("DNS-over-TLS")
    if dest_doh_certain(dest) or dest_uses_doh(dest):
        # Hostname match is certain; 443 to a public resolver is still labelled so
        # the report can show the protocol next to the IP.
        protocols.add("DNS-over-HTTPS")


def is_cgnat(ip: str) -> bool:
    """RFC 6598 shared address space 100.64.0.0/10 (carrier-grade NAT / P2P peers)."""
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return False


# RFC 1918 / ULA: addresses a real device on your own Wi-Fi can actually hold.
HOME_LAN_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                 "fe80::/10", "fc00::/7")

# Special-use / documentation / bogon ranges. Python's ipaddress marks some of these
# (e.g. 192.0.0.0/24) as "private", which wrongly made them look like LAN peers. A real
# home device is never addressed from these; when one shows up as a "LAN peer" it is almost
# always a placeholder/DS-Lite address or an address carried *inside* P2P/STUN signalling.
SPECIAL_USE_NETS = {
    "0.0.0.0/8": "unspecified/this-network (0.0.0.0/8)",
    "192.0.0.0/24": "IETF protocol-assignment / DS-Lite space (192.0.0.0/24)",
    "192.0.2.0/24": "documentation TEST-NET-1 (192.0.2.0/24)",
    "198.51.100.0/24": "documentation TEST-NET-2 (198.51.100.0/24)",
    "203.0.113.0/24": "documentation TEST-NET-3 (203.0.113.0/24)",
    "198.18.0.0/15": "benchmarking (198.18.0.0/15)",
    "240.0.0.0/4": "reserved (240.0.0.0/4)",
    "2001:db8::/32": "documentation (2001:db8::/32)",
    "100::/64": "discard-only (100::/64)",
}


def _in_any(ip: str, nets) -> str | None:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net in nets:
        try:
            if a in ipaddress.ip_network(net):
                return net
        except ValueError:
            continue
    return None


def is_home_lan(ip: str) -> bool:
    """True for addresses a device on your own Wi-Fi/LAN can genuinely hold (RFC1918 + IPv6 LL/ULA)."""
    return _in_any(ip, HOME_LAN_NETS) is not None


def is_special_use(ip: str) -> bool:
    """True for documentation/reserved/protocol-assignment ranges (incl. 192.0.0.0/24)."""
    return _in_any(ip, SPECIAL_USE_NETS) is not None


def special_use_label(ip: str) -> str:
    net = _in_any(ip, SPECIAL_USE_NETS)
    base = SPECIAL_USE_NETS.get(net, "special-use address")
    return (f"special-use {base}, not a real device on your Wi-Fi; "
            "likely a placeholder/DS-Lite address or one carried inside P2P/STUN signalling")


def is_ipv6(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).version == 6
    except ValueError:
        return False

