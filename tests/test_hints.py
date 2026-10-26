"""Offline known-issue hints.

Fixtures use documentation and LAN addresses (RFC 5737, 192.168.1.0/24) and a
locally administered MAC. No live host is contacted.
"""

from __future__ import annotations

import socket

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from iotaudit.analyze import build_devices, to_dict
from iotaudit.capture import Collector
from iotaudit.grading import grade
from iotaudit.hints import VERIFY_PHRASE, hints_for_device, load_catalog, match_observations
from iotaudit.report import render_html
from iotaudit.scan import parse_nmap_xml

_DASHES = ("\u2014", "\u2013", "&mdash;", "&ndash;")
DEVICE = "192.168.1.40"
MAC = "02:00:00:00:00:0a"
OTHER = "192.0.2.10"


def _port(port, service, product="", version="", extrainfo="", **extra) -> dict:
    row = {
        "port": port,
        "proto": "tcp",
        "service": service,
        "product": " ".join(x for x in (product, version) if x),
        "product_name": product,
        "version": version,
        "extrainfo": extrainfo,
    }
    row.update(extra)
    return row


def _hints(ports=None, banners=None, upnp=None, ip=DEVICE):
    device = {"ip": ip, "open_ports": list(ports or []), "service_banners": list(banners or [])}
    return hints_for_device(device, upnp=upnp)


def _cves(hints) -> set[str]:
    return {h["cve"] for h in hints}


def test_catalog_is_small_cited_and_local():
    entries = load_catalog()
    assert 10 <= len(entries) <= 20
    for entry in entries:
        assert entry["cve"].startswith("CVE-")
        assert entry["reference"] == f"https://nvd.nist.gov/vuln/detail/{entry['cve']}"
        assert entry["severity"] in ("low", "medium", "high", "critical")
        for dash in _DASHES:
            assert dash not in entry["title"] and dash not in entry["summary"]
    again = load_catalog()
    assert [e["cve"] for e in again] == [e["cve"] for e in entries]


def test_matcher_does_not_open_a_socket(monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("known-issue matching must stay offline")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    hints = _hints([_port(22, "ssh", "Dropbear sshd", "2016.70")])
    assert "CVE-2016-3116" in _cves(hints)


def test_version_rules_and_grade():
    # Exact critical: MiniUPnPd 1.0 (CVE-2013-0230) moves the grade by 25.
    old = _hints([_port(80, "http", "miniupnpd", "1.0")])
    assert "CVE-2013-0230" in _cves(old)
    assert any(h["match_exact"] and h["affects_grade"] for h in old if h["cve"] == "CVE-2013-0230")
    # 1.0 is also before 1.4, so the SSDP crash is a range hint and does not score.
    crash = next(h for h in old if h["cve"] == "CVE-2013-0229")
    assert crash["match_exact"] is False and crash["affects_grade"] is False
    assert grade([], old) == (75, "B")
    assert grade([]) == (100, "A")

    # Same product, fixed generation: no SOAP overflow hint, no grade change.
    newer = _hints([_port(80, "http", "miniupnpd", "2.1")])
    assert "CVE-2013-0230" not in _cves(newer)
    assert "CVE-2013-0229" not in _cves(newer)
    assert grade([], newer) == (100, "A")

    # 1.2 is in the SSDP range only.
    mid = _hints([_port(80, "http", "miniupnpd", "1.2")])
    assert _cves(mid) == {"CVE-2013-0229"}
    assert grade([], mid) == (100, "A")


def test_open_service_without_a_cited_banner_is_not_a_hint():
    telnet = _hints([_port(23, "telnet")])
    rtsp = _hints([_port(554, "rtsp", extrainfo="no authentication")])
    upnp = _hints([_port(1900, "upnp", proto="udp")])
    assert telnet == [] and rtsp == [] and upnp == []
    assert grade([], telnet) == (100, "A")


def test_product_ranges_do_not_change_the_grade():
    dropbear = _hints([_port(22, "ssh", "Dropbear sshd", "2016.70")])
    assert _cves(dropbear) == {"CVE-2016-3116", "CVE-2018-15599", "CVE-2023-48795"}
    assert all(h["affects_grade"] is False for h in dropbear)
    assert grade([], dropbear) == (100, "A")
    assert _hints([_port(22, "ssh", "Dropbear sshd", "2022.84")]) == []
    assert _cves(_hints([_port(22, "ssh", "Dropbear sshd", "2018.76")])) == {
        "CVE-2018-15599", "CVE-2023-48795",
    }
    assert "CVE-2016-3116" not in _cves(_hints([_port(22, "ssh", "Dropbear sshd", "2016.72")]))

    busy_old = _hints([_port(23, "telnet", "BusyBox telnetd", "1.18.4")])
    assert _cves(busy_old) == {"CVE-2021-42378"}
    assert grade([], busy_old) == (100, "A")
    busy_exact = _hints([_port(23, "telnet", "BusyBox telnetd", "1.33.1")])
    hush = next(h for h in busy_exact if h["cve"] == "CVE-2021-42377")
    assert hush["match_exact"] is True and hush["affects_grade"] is False
    assert "CVE-2021-42378" in _cves(busy_exact)
    assert grade([], busy_exact) == (100, "A")
    assert _hints([_port(23, "telnet", "BusyBox telnetd", "1.15.3")]) == []
    assert _hints([_port(23, "telnet", "BusyBox telnetd", "1.34.0")]) == []

    go_exact = _hints([_port(80, "http", "GoAhead-Webs", "3.6.4")])
    go = go_exact[0]
    assert go["cve"] == "CVE-2017-17562" and go["match_exact"] is True
    assert go["affects_grade"] is False and grade([], go_exact) == (100, "A")
    go_old = _hints([_port(80, "http", "GoAhead-Webs", "2.5.0")])
    assert go_old[0]["match_exact"] is False and go_old[0]["cve"] == "CVE-2017-17562"
    assert _hints([_port(80, "http", "GoAhead-Webs", "3.6.5")]) == []

    assert _cves(_hints([_port(80, "http", "lighttpd", "1.4.35")])) == {"CVE-2018-19052"}
    assert _cves(_hints([_port(80, "http", "lighttpd", "1.4.64")])) == {"CVE-2022-41556"}
    assert _hints([_port(80, "http", "lighttpd", "1.4.50")]) == []
    assert _hints([_port(80, "http", "lighttpd", "1.4.55")]) == []
    assert _hints([_port(80, "http", "lighttpd", "1.4.67")]) == []


def test_critical_exact_versions_move_the_grade_and_nearby_ones_do_not():
    rom = _hints([_port(80, "http", "RomPager", "4.07")])
    assert rom[0]["cve"] == "CVE-2014-9222" and rom[0]["affects_grade"] is True
    assert grade([], rom) == (75, "B")
    assert _hints([_port(80, "http", "RomPager", "4.34")]) == []
    assert _hints([_port(80, "http", "RomPager", "4.06")]) == []

    old_netkit = _hints([_port(23, "telnet", "netkit-telnetd", "0.16")])
    assert old_netkit[0]["cve"] == "CVE-2020-10188"
    assert old_netkit[0]["match_exact"] is False and old_netkit[0]["affects_grade"] is False
    assert grade([], old_netkit) == (100, "A")
    exact_netkit = _hints([_port(23, "telnet", "netkit-telnetd", "0.17")])
    assert exact_netkit[0]["affects_grade"] is True
    assert grade([], exact_netkit) == (75, "B")
    assert _hints([_port(23, "telnet", "netkit-telnetd", "0.17.41")]) == []
    # BusyBox telnetd is not netkit telnetd.
    assert "CVE-2020-10188" not in _cves(_hints([_port(23, "telnet", "BusyBox telnetd", "1.18.4")]))

    live_exact = _hints([_port(554, "rtsp", "LIVE555 Streaming Media", "0.92")])
    assert live_exact[0]["cve"] == "CVE-2018-4013" and live_exact[0]["affects_grade"] is True
    assert grade([], live_exact) == (75, "B")
    live_date = _hints([_port(554, "rtsp", "LIVE555 Streaming Media", "2018.02.28")])
    assert live_date[0]["match_exact"] is False and live_date[0]["affects_grade"] is False
    assert grade([], live_date) == (100, "A")
    assert _hints([_port(554, "rtsp", "LIVE555 Streaming Media", "2018.10.17")]) == []

    both = rom + exact_netkit
    assert grade([], both) == (50, "D")


def test_critical_exact_hint_still_moves_a_capped_score():
    findings = [{"severity": "info", "category": "coverage", "title": "Limited", "detail": "Thin capture."}]
    assert grade(findings) == (70, "C")
    hint = {"match_exact": True, "severity": "critical"}
    assert grade(findings, [hint]) == (45, "D")
    hint["severity"] = "high"
    assert grade(findings, [hint]) == (70, "C")
    hint["severity"] = "critical"
    hint["match_exact"] = False
    assert grade(findings, [hint]) == (70, "C")


def test_phrase_reference_and_no_dashes():
    hints = _hints([_port(80, "http", "RomPager", "4.07", extrainfo="no authentication")])
    hint = hints[0]
    assert VERIFY_PHRASE in hint["detail"]
    assert hint["detail"].endswith(VERIFY_PHRASE + ".")
    assert hint["reference"].startswith("https://nvd.nist.gov/vuln/detail/CVE-2014-9222")
    assert "did not ask for authentication" in hint["observed"]
    for dash in _DASHES:
        assert dash not in hint["detail"] and dash not in hint["title"]


def test_upnp_igd_hint_stays_on_that_router():
    upnp = {"routers": [{
        "location": "http://192.168.1.1:5000/rootDesc.xml",
        "igd": True,
        "name": "LAN gateway",
        "model": "HR-1",
    }]}
    router = _hints(upnp=upnp, ip="192.168.1.1")
    assert _cves(router) == {"CVE-2020-12695"}
    assert router[0]["match_exact"] is False and router[0]["affects_grade"] is False
    assert VERIFY_PHRASE in router[0]["detail"]
    assert grade([], router) == (100, "A")
    assert _hints(upnp=upnp, ip=IP) == []


def test_rtsp_without_auth_is_recorded_only_with_a_matching_banner():
    bare = banner = {
        "source": "rtsp",
        "service": "rtsp",
        "port": 554,
        "product": "",
        "version": "",
        "banner": "",
        "server": "",
        "device_type": "",
        "unauthenticated": True,
        "text": "",
    }
    assert match_observations([bare], load_catalog()) == []
    banner = {
        **bare,
        "product": "LIVE555 Streaming Media",
        "server": "LIVE555 Streaming Media 0.92",
        "text": "LIVE555 Streaming Media 0.92",
    }
    hints = match_observations([banner], load_catalog())
    assert hints[0]["cve"] == "CVE-2018-4013" and hints[0]["affects_grade"] is True
    assert "did not ask for authentication" in hints[0]["observed"]

    entry = dict(load_catalog()[0])
    entry["match"] = {**entry["match"], "require_unauthenticated": True, "products": ["live555"]}
    entry["match"]["versions_exact"] = ["0.92"]
    assert match_observations([bare], [entry]) == []
    assert match_observations([banner], [entry])[0]["cve"] == entry["cve"]


def test_nmap_product_version_and_report_json():
    xml = """<nmaprun><host><ports>
    <port protocol="tcp" portid="80"><state state="open"/>
    <service name="http" product="lighttpd" version="1.4.35"/></port>
    <port protocol="tcp" portid="23"><state state="open"/>
    <service name="telnet" product="BusyBox telnetd"/></port>
    </ports></host></nmaprun>"""
    ports = parse_nmap_xml(xml)
    light = ports[0]
    assert light["product"] == "lighttpd 1.4.35"
    assert light["product_name"] == "lighttpd" and light["version"] == "1.4.35"
    assert ports[1]["version"] == "" and ports[1]["risk"] == "high"
    hints = _hints(ports)
    assert _cves(hints) == {"CVE-2018-19052"}
    assert all(VERIFY_PHRASE in h["detail"] for h in hints)

    col = Collector([DEVICE])
    col.macs[DEVICE] = MAC
    pkt = Ether(src=MAC, dst="02:00:00:00:00:01") / IP(src=DEVICE, dst=OTHER) / TCP(dport=443, sport=40000)
    col.add(pkt)
    dev = build_devices(col, scans={DEVICE: ports})[0]
    assert dev.score == grade(dev.findings, dev.known_issue_hints)[0]
    bare_score, _letter = grade(dev.findings)
    assert dev.score == bare_score
    report = to_dict(dev)
    assert report["known_issue_hints"][0]["cve"] == "CVE-2018-19052"
    assert "known_issue_hints" in report
    html = render_html([report])
    assert "Known issue hints" in html
    assert "CVE-2018-19052" in html
    assert VERIFY_PHRASE in html
    assert "does not change the grade" in html
    assert "nvd.nist.gov/vuln/detail/CVE-2018-19052" in html
    for dash in _DASHES:
        assert dash not in html
    assert DEVICE in html and MAC in html
    assert "example.com" not in html


def test_captured_http_and_ssdp_banners():
    col = Collector([DEVICE])
    col.macs[DEVICE] = MAC
    http = (
        b"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.64\r\nContent-Length: 0\r\n\r\n"
    )
    ssdp = (
        b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        b"SERVER: miniupnpd/1.0 UPnP/1.1\r\n"
        b"NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
        b"USN: uuid:00000000-0000-0000-0000-000000000000\r\n\r\n"
    )
    base = Ether(src=MAC, dst="02:00:00:00:00:01")
    col.add(base / IP(src=DEVICE, dst="192.168.1.20") / TCP(sport=80, dport=50000) / http)
    col.add(base / IP(src=DEVICE, dst="239.255.255.250") / UDP(sport=1900, dport=1900) / ssdp)
    dev = build_devices(col)[0]
    cves = _cves(dev.known_issue_hints)
    assert "CVE-2022-41556" in cves
    assert "CVE-2013-0230" in cves
    assert "CVE-2020-12695" in cves
    assert any(h["affects_grade"] and h["cve"] == "CVE-2013-0230" for h in dev.known_issue_hints)
    report = to_dict(dev)
    assert report["grade"] == grade(dev.findings, dev.known_issue_hints)[1]
    bare = grade(dev.findings)
    assert report["score"] == bare[0] - 25
    html = render_html([report])
    assert "counts toward the grade" in html
    assert VERIFY_PHRASE in html


def test_require_unauthenticated_blocks_a_banner_that_asked_for_auth():
    entry = {
        "id": "live555-needs-unauth",
        "cve": "CVE-2018-4013",
        "severity": "critical",
        "title": "LIVE555",
        "summary": "LIVE555 0.92 header parsing issue (CVE-2018-4013).",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2018-4013",
        "match": {
            "products": ["live555"],
            "versions_exact": ["0.92"],
            "require_unauthenticated": True,
        },
    }
    hidden = {
        "source": "rtsp", "service": "rtsp", "port": 554,
        "product": "LIVE555 Streaming Media", "version": "0.92",
        "server": "LIVE555 Streaming Media 0.92", "banner": "",
        "device_type": "", "unauthenticated": False,
        "text": "LIVE555 Streaming Media 0.92",
    }
    assert match_observations([hidden], [entry]) == []
    hidden["unauthenticated"] = True
    hit = match_observations([hidden], [entry])
    assert hit[0]["affects_grade"] is True
    for dash in _DASHES:
        assert dash not in hit[0]["detail"]


def test_mcp_analyze_mentions_hints():
    import asyncio

    from iotaudit.mcp_server import create_server

    tools = asyncio.run(create_server().list_tools())
    analyze = next(tool for tool in tools if tool.name == "analyze_pcap")
    assert "known_issue_hints" in (analyze.description or "")
