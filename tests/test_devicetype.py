"""Evidence-based device-type identification and PCAPdroid (Android) pcap import."""

from __future__ import annotations

from iotaudit.analyze import build_devices, to_dict
from iotaudit.capture import Collector
from iotaudit.devicetype import identify_device_type, type_from_report
from iotaudit.models import Flow


def test_type_camera_two_sources_high():
    r = identify_device_type(open_ports=[554], domains=["p2p.dahua.com"])
    assert r["type"] == "camera" and r["confidence"] == "high"


def test_type_single_strong_domain_is_medium():
    r = identify_device_type(domains=["api.roborock.com"])
    assert r["type"] == "robot-vacuum" and r["confidence"] == "medium"


def test_type_oui_only_is_low():
    r = identify_device_type(vendor="TP-LINK TECHNOLOGIES CO.,LTD")
    assert r["type"] == "plug/bulb" and r["confidence"] == "low"


def test_type_printer_port_plus_mdns_high():
    r = identify_device_type(open_ports=[9100], mdns=["_ipp._tcp.local."])
    assert r["type"] == "printer" and r["confidence"] == "high"


def test_type_nas_and_tv_and_speaker():
    assert identify_device_type(open_ports=[5000], domains=["x.quickconnect.to"])["type"] == "nas"
    assert identify_device_type(domains=["ws.samsungcloudsolution.com"],
                                open_ports=[8001])["type"] == "tv"
    assert identify_device_type(mdns=["_raop._tcp.local."])["type"] == "speaker"


def test_type_unknown_when_no_evidence():
    r = identify_device_type()
    assert r["type"] is None and r["confidence"] == "unknown"


def test_type_from_report_uses_destinations():
    rep = {
        "vendor": "Hangzhou Hikvision",
        "dns_queries": ["dev.hik-connect.com"],
        "destinations": [{"domains": ["dev.hik-connect.com"], "ports": [443]}],
        "open_ports": [{"port": 554}],
    }
    r = type_from_report(rep)
    assert r["type"] == "camera" and r["confidence"] == "high"


def test_build_devices_sets_device_type():
    col = Collector(["192.168.0.40"])
    col.queries["192.168.0.40"] = {"api.roborock.com"}
    col.dns["1.2.3.4"] = {"api.roborock.com"}
    col.flows[("192.168.0.40", "1.2.3.4", 443, "tcp")] = Flow(
        "192.168.0.40", "1.2.3.4", 443, "tcp", bytes=5000, packets=10, tls=True)
    d = to_dict(build_devices(col)[0])
    assert d["device_type"]["type"] == "robot-vacuum"
    assert "Looks like a Robot vacuum" in d["summary"]
