"""Bundled device profiles and hostname matching."""

from iotaudit.analyze import build_devices, to_dict
from iotaudit.capture import Collector
from iotaudit.models import Destination, Device, Flow
from iotaudit.profiles import is_expected, load_profiles, match_profile


def _ids():
    return {p["id"] for p in load_profiles()}


def test_new_profiles_load():
    ids = _ids()
    assert "ring-doorbell" in ids
    assert "philips-hue-bridge" in ids
    assert "shelly" in ids
    assert "sonoff-ewelink" in ids
    # existing profiles still present
    assert "tuya-generic" in ids
    assert "xiaomi-miio" in ids


def _device(ip="192.0.2.50", vendor=None, hostname=None, domains=()):
    dev = Device(ip=ip, vendor=vendor, hostname=hostname)
    for i, name in enumerate(domains):
        dest_ip = f"203.0.113.{10 + i}"
        d = Destination(ip=dest_ip, ports={443}, encrypted=True, bytes_out=4000)
        d.domains.add(name)
        dev.destinations[dest_ip] = d
        dev.dns_queries.add(name)
    return dev


def test_ring_matches_ring_com_not_generic_amazon():
    profiles = load_profiles()
    ring = match_profile(_device(domains=["api.ring.com"]), profiles)
    assert ring and ring["id"] == "ring-doorbell"
    assert is_expected(["fw.ring.com"], ring) is True
    assert is_expected(["s3.amazonaws.com"], ring) is True
    assert is_expected(["tracker.example.com"], ring) is False
    # Amazon cloud alone must not attach the Ring profile
    amazon = match_profile(_device(vendor="Amazon Technologies", domains=["s3.amazonaws.com"]), profiles)
    assert amazon is None or amazon["id"] != "ring-doorbell"


def test_hue_matches_domain_or_hostname_not_signify_vendor_alone():
    profiles = load_profiles()
    by_dns = match_profile(_device(domains=["discovery.meethue.com"]), profiles)
    assert by_dns and by_dns["id"] == "philips-hue-bridge"
    by_name = match_profile(_device(hostname="Hue-Bridge-1A2B3C"), profiles)
    assert by_name and by_name["id"] == "philips-hue-bridge"
    vendor_only = match_profile(_device(vendor="Signify B.V."), profiles)
    assert vendor_only is None or vendor_only["id"] != "philips-hue-bridge"
    assert is_expected(["api.meethue.com"], by_dns) is True
    assert is_expected(["wizconnected.com"], by_dns) is False


def test_shelly_matches_hostname_without_cloud():
    profiles = load_profiles()
    # Cloud can be disabled; the default hostname is still distinctive.
    prof = match_profile(_device(hostname="shellyplus1-aabbcc"), profiles)
    assert prof and prof["id"] == "shelly"
    by_vendor = match_profile(_device(vendor="Shelly Europe"), profiles)
    assert by_vendor and by_vendor["id"] == "shelly"
    by_dns = match_profile(_device(domains=["api.shelly.cloud"]), profiles)
    assert by_dns and by_dns["id"] == "shelly"


def test_sonoff_does_not_steal_tuya():
    profiles = load_profiles()
    tuya = match_profile(_device(vendor="Tuya Smart", domains=["m2.tuyaeu.com"]), profiles)
    assert tuya and tuya["id"] in {"tuya-generic", "imipaw-pettech-feeder"}
    sonoff = match_profile(_device(vendor="SHENZHEN Coolkit Technology", domains=["eu-dispa.ewelink.cc"]), profiles)
    assert sonoff and sonoff["id"] == "sonoff-ewelink"
    # Espressif vendor with no eWeLink/Tuya domain is not labelled Sonoff
    espressif = match_profile(_device(vendor="Espressif"), profiles)
    assert espressif is None or espressif["id"] != "sonoff-ewelink"


def _collect(ip, mac, queries, flows, hostname=None):
    col = Collector([ip])
    if mac:
        col.macs[ip] = mac
    col.queries[ip] = set(queries)
    known = []
    if hostname:
        known.append({"ip": ip, "mac": mac, "hostname": hostname})
    for dst, port, domain, tls in flows:
        if domain:
            col.dns[dst] = {domain}
        col.flows[(ip, dst, port, "tcp")] = Flow(
            ip, dst, port, "tcp", bytes=8000, packets=20, tls=tls
        )
    devs = build_devices(col, known_devices=known or None)
    return to_dict(devs[0])


def test_ring_report_flags_unexpected_destination():
    d = _collect(
        "192.0.2.50",
        "02:00:00:00:00:11",
        {"api.ring.com", "ads.example.com"},
        [
            ("203.0.113.10", 443, "api.ring.com", True),
            ("203.0.113.20", 443, "ads.example.com", True),
        ],
    )
    assert d["profile"] and "Ring" in d["profile"]
    dests = {x["ip"]: x for x in d["destinations"]}
    assert dests["203.0.113.10"]["expected"] is True
    assert dests["203.0.113.20"]["expected"] is False
    assert any("not in device profile" in f["title"] for f in d["findings"])


def test_shelly_report_matches_hostname_when_cloud_is_off():
    d = _collect(
        "192.0.2.60",
        "02:00:00:00:00:12",
        {"pool.ntp.org"},
        [("203.0.113.123", 123, "pool.ntp.org", False)],
        hostname="shellyplus1-aabbcc",
    )
    assert d["profile"] and "Shelly" in d["profile"]
    assert d["hostname"] == "shellyplus1-aabbcc"
