"""Offline enrichment: country (optional GeoLite2 .mmdb), organisation/vendor from domain,
MAC vendor (small built-in OUI table), tracker detection. No network calls, no telemetry."""

from __future__ import annotations

import os

# Domain suffix -> organisation. Extend via profiles / PRs.
DOMAIN_ORGS = {
    "amazonaws.com": "Amazon AWS", "aws.amazon.com": "Amazon AWS", "cloudfront.net": "Amazon CloudFront",
    "googleapis.com": "Google", "google.com": "Google", "gstatic.com": "Google",
    "1e100.net": "Google", "azure.com": "Microsoft Azure", "microsoft.com": "Microsoft",
    "tuya.com": "Tuya", "tuyaeu.com": "Tuya", "tuyaus.com": "Tuya", "tuyacn.com": "Tuya",
    "aliyuncs.com": "Alibaba Cloud", "alibaba.com": "Alibaba", "xiaomi.com": "Xiaomi",
    "mi.com": "Xiaomi", "io.mi.com": "Xiaomi", "akamaiedge.net": "Akamai", "akamai.net": "Akamai",
    "cloudflare.com": "Cloudflare", "ntp.org": "NTP Pool", "apple.com": "Apple",
    "icloud.com": "Apple", "facebook.com": "Meta", "doubleclick.net": "Google Ads",
    "umeng.com": "Umeng (Alibaba analytics)", "bugly.qq.com": "Tencent Bugly", "qq.com": "Tencent",
}

# Minimal tracker/analytics list; full list import (e.g. DuckDuckGo Tracker Radar) planned.
TRACKERS = {
    "doubleclick.net", "google-analytics.com", "app-measurement.com", "umeng.com",
    "bugly.qq.com", "crashlytics.com", "branch.io", "adjust.com", "appsflyer.com",
    "graph.facebook.com", "segment.io", "mixpanel.com", "amplitude.com", "sentry.io",
}

# Small OUI sample; `iotaudit` reads a full IEEE oui.txt if IOTAUDIT_OUI points to one.
OUI = {
    "d8:1f:12": "Tuya Smart", "10:d5:61": "Tuya Smart", "68:57:2d": "Tuya Smart",
    "50:ec:50": "Beijing Xiaomi", "64:90:c1": "Beijing Xiaomi", "78:11:dc": "Xiaomi",
    "24:0a:c4": "Espressif", "30:ae:a4": "Espressif", "84:f3:eb": "Espressif",
    "a4:cf:12": "Espressif", "ec:fa:bc": "Espressif", "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi", "f0:9f:c2": "Ubiquiti", "44:65:0d": "Amazon",
    "fc:65:de": "Amazon", "e8:ab:fa": "Shenzhen Reecam (cameras)", "9c:8e:cd": "Amcrest",
}


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


def mac_vendor(mac: str | None) -> str | None:
    global _oui_cache
    if not mac:
        return None
    prefix = mac.lower()[:8]
    if _oui_cache is None:
        _oui_cache = dict(OUI)
        path = os.environ.get("IOTAUDIT_OUI")
        if path and os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if "(hex)" in line:
                        hexp, _, org = line.partition("(hex)")
                        _oui_cache[hexp.strip().replace("-", ":").lower()] = org.strip()
    if int(prefix[1], 16) & 2:
        return "Randomized MAC"
    return _oui_cache.get(prefix)


class Geo:
    """Country lookup using a local GeoLite2/DB-IP country .mmdb (set IOTAUDIT_GEOIP or --geoip)."""

    def __init__(self, path: str | None = None):
        self.reader = None
        path = path or os.environ.get("IOTAUDIT_GEOIP")
        if path and os.path.exists(path):
            try:
                import maxminddb

                self.reader = maxminddb.open_database(path)
            except ImportError:
                self.reader = None

    def country(self, ip: str) -> str | None:
        if not self.reader:
            return None
        rec = self.reader.get(ip) or {}
        c = rec.get("country") or rec.get("registered_country") or {}
        return c.get("iso_code")
