from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.tls.extensions import ServerName, TLS_Ext_ServerName
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
from scapy.utils import wrpcap

from iotaudit.analyze import build_devices, to_dict
from iotaudit.capture import Collector, from_pcap, parse_client_hello, parse_http_host
from iotaudit.consent import require_consent
from iotaudit.grading import grade
from iotaudit.report import render_html
from iotaudit.scan import parse_nmap_xml

HTTP_REQ = b"GET /up HTTP/1.1\r\nHost: log.umeng.com\r\n\r\n"
DEV, MAC = "192.168.12.50", "d8:1f:12:aa:bb:cc"


def client_hello(sni):
    return bytes(TLS(msg=[TLSClientHello(ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=sni)])])]))


def packets():
    e = Ether(src=MAC, dst="00:11:22:33:44:55")
    return [
        e / IP(src="192.168.12.1", dst=DEV) / UDP(sport=53, dport=5353) / DNS(
            qr=1, qd=DNSQR(qname="a1.tuyaeu.com"), an=DNSRR(rrname="a1.tuyaeu.com", rdata="3.120.1.1")),
        e / IP(src=DEV, dst="192.168.12.1") / UDP(dport=53) / DNS(qd=DNSQR(qname="a1.tuyaeu.com")),
        e / IP(src=DEV, dst="3.120.1.1") / TCP(dport=443, flags="PA") / client_hello("a1.tuyaeu.com"),
        e / IP(src=DEV, dst="47.1.2.3") / TCP(dport=80, flags="PA") / HTTP_REQ,
    ]


def test_parsers():
    ver, sni = parse_client_hello(client_hello("x.example.com"))
    assert sni == "x.example.com" and ver
    assert parse_http_host(b"GET / HTTP/1.1\r\nHost: a.b\r\n\r\n") == "a.b"
    assert parse_http_host(b"\x16\x03") is None


def test_pipeline(tmp_path):
    pcap = tmp_path / "t.pcap"
    wrpcap(str(pcap), packets())
    devs = [to_dict(d) for d in build_devices(from_pcap(str(pcap), Collector([DEV])))]
    assert len(devs) == 1
    d = devs[0]
    assert d["vendor"] and ("Tuya" in (d["vendor"] or "") or "Tuya" in (d["profile"] or "") or d["profile"])
    dests = {x["ip"]: x for x in d["destinations"]}
    assert dests["3.120.1.1"]["encrypted"] and dests["3.120.1.1"]["expected"]
    assert not dests["47.1.2.3"]["encrypted"] and dests["47.1.2.3"]["tracker"]
    assert d["grade"] in "CDEF"
    # Observed findings stay certain. Pattern matches carry their own confidence.
    for f in d["findings"]:
        assert f["category"]
        if f["title"].startswith("Traffic pattern"):
            assert f["confidence"] in ("low", "medium", "high")
            assert "indicator" in f["title"]
            assert "Indicator only" in f["detail"]
        else:
            assert f["confidence"] == "certain"
    assert {c["country"] for c in d["destination_countries"]} == {"DE", "US"}
    assert any(p["label"] == "telemetry" and p["kind"] == "indicator" for p in d["traffic_patterns"])
    html = render_html(devs)
    assert "tuyaeu.com" in html and DEV in html
    assert "Destination countries" in html and "Traffic patterns" in html
    assert "\u2014" not in html and "&mdash;" not in html


def test_grade_and_nmap():
    assert grade([]) == (100, "A")
    assert grade([{"severity": "high"}] * 4)[1] == "F"
    xml = """<nmaprun><host><ports><port protocol="tcp" portid="23"><state state="open"/>
    <service name="telnet" product="BusyBox telnetd"/></port></ports></host></nmaprun>"""
    p = parse_nmap_xml(xml)
    assert p[0]["port"] == 23 and p[0]["risk"] == "high"


def test_consent():
    import io
    assert require_consent(stream_in=io.StringIO("i own this network\n"), stream_out=io.StringIO())
    assert not require_consent(stream_in=io.StringIO("yes\n"), stream_out=io.StringIO())


def test_mcp_tools():
    import asyncio

    from iotaudit.mcp_server import create_server

    names = {t.name for t in asyncio.run(create_server().list_tools())}
    assert {"analyze_pcap", "capture", "scan_device", "diff_results"} <= names


def test_arp_safety_and_forwarding():
    import iotaudit.arp as arp

    # refuses public IPs
    try:
        arp.ArpSpoofer("8.8.8.8", "192.168.1.1", "en0")
        raise AssertionError("public IP should be rejected")
    except ValueError:
        pass
    # IPForwarding knows a key on supported platforms (Linux CI)
    f = arp.IPForwarding()
    assert f.key in (None, "net.ipv4.ip_forward", "net.inet.ip.forwarding")


def test_imipaw_profile_loads():
    from iotaudit.profiles import load_profiles

    ids = {p["id"] for p in load_profiles()}
    assert "imipaw-pettech-feeder" in ids


def test_discover_format_and_pick():
    import io

    from iotaudit.discover import format_table, pick

    devs = [
        {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Ubiquiti",
         "hostname": "router", "role": "router", "likely_iot": False},
        {"ip": "192.168.1.50", "mac": "d8:1f:12:00:00:01", "vendor": "Tuya Smart",
         "hostname": None, "role": None, "likely_iot": True},
        {"ip": "192.168.1.10", "mac": "00:03:93:00:00:01", "vendor": "Apple",
         "hostname": None, "role": "this-host", "likely_iot": False},
    ]
    # Pretend identify already ran
    for d, looks in zip(devs, ["Router / gateway", "Tuya device (port 6668 open)", "This Mac / PC"], strict=True):
        d["looks_like"] = looks
        d["id_confidence"] = "high"
    t = format_table(devs)
    assert "Tuya device (port 6668 open)" in t and "192.168.1.50" in t
    assert "Router / gateway" in t and "This Mac / PC" in t
    assert pick(devs, io.StringIO("2\n"), io.StringIO())["ip"] == "192.168.1.50"
    assert pick(devs, io.StringIO("q\n"), io.StringIO()) is None
    assert pick(devs, io.StringIO("9\n"), io.StringIO()) is None
    assert pick([], io.StringIO("1\n"), io.StringIO()) is None


MACOS_ARP_A = """\
? (192.168.1.1) at 0:1a:2b:3:4:5 on en0 ifscope [ethernet]
router.home (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
? (192.168.1.50) at d8:1f:12:a:b:c on en0 ifscope [ethernet]
? (192.168.1.60) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.70) at 2:0:0:0:0:1 on en0 ifscope [ethernet]
"""

LINUX_IP_NEIGH = """\
192.168.1.1 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.1.50 lladdr d8:1f:12:0a:0b:0c STALE
192.168.1.60 FAILED
"""


def test_normalize_mac_and_vendor_macos():
    from iotaudit.enrich import mac_vendor, normalize_mac

    assert normalize_mac("0:1a:2b:3:4:5") == "00:1a:2b:03:04:05"
    assert normalize_mac("d8:1f:12:a:b:c") == "d8:1f:12:0a:0b:0c"
    assert normalize_mac("(incomplete)") is None
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("bad") is None
    assert normalize_mac(":::") is None
    # unpadded Tuya OUI must still resolve (this was the Sequoia crash)
    assert mac_vendor("d8:1f:12:a:b:c") == "Tuya Smart"
    assert mac_vendor("0:1a:2b:3:4:5")  # resolves via bundled OUI, must not raise
    assert mac_vendor("2:0:0:0:0:1") == "random (phone/laptop)"  # LAA bit
    assert mac_vendor("(incomplete)") is None
    assert mac_vendor(":") is None
    assert mac_vendor("") is None


def test_parse_macos_arp_a_and_netmask():
    from iotaudit.discover import _parse_netmask_hex, parse_arp_a

    table = parse_arp_a(MACOS_ARP_A)
    assert "192.168.1.60" not in table  # incomplete skipped
    assert table["192.168.1.50"] == "d8:1f:12:0a:0b:0c"
    assert table["192.168.1.1"] in ("00:1a:2b:03:04:05", "aa:bb:cc:dd:ee:ff")
    assert table["192.168.1.70"] == "02:00:00:00:00:01"
    linux = parse_arp_a(LINUX_IP_NEIGH)
    assert linux["192.168.1.50"] == "d8:1f:12:0a:0b:0c"
    assert "192.168.1.60" not in linux
    assert _parse_netmask_hex("0xffffff00") == 24
    assert _parse_netmask_hex("0xffff0000") == 16
    assert _parse_netmask_hex("255.255.255.0") == 24
    assert _parse_netmask_hex("bogus") is None



def test_bundled_oui_table_lookup():
    """Representative vendor prefixes resolve via the bundled IEEE OUI table."""
    from iotaudit.discover import _is_multicast
    from iotaudit.enrich import is_likely_iot, mac_vendor

    expected = {
        "00:09:5b:00:00:01": "NETGEAR",
        "70:87:9e:00:00:01": "Beken",
        "00:0a:eb:00:00:01": "TP-LINK",
        "00:e0:4c:00:00:01": "REALTEK",
        "00:00:f0:00:00:01": "Samsung",
        "00:04:3c:00:00:01": "SONOS",
        "84:00:ec:00:00:01": "Shelly",
        "00:03:93:00:00:01": "Apple",
        "00:bc:99:00:00:01": "Hikvision",
    }
    for mac, needle in expected.items():
        v = mac_vendor(mac)
        assert v and needle.lower() in v.lower(), (mac, v)
    assert is_likely_iot(mac_vendor("70:87:9e:00:00:01"))
    assert is_likely_iot(mac_vendor("84:00:ec:00:00:01"))
    assert is_likely_iot(mac_vendor("00:bc:99:00:00:01"))
    assert not is_likely_iot(mac_vendor("00:03:93:00:00:01"))
    assert _is_multicast("224.0.0.251")
    assert not _is_multicast("192.168.1.50")


def test_arp_sweep_skips_multicast(monkeypatch):
    from iotaudit import discover

    monkeypatch.setattr(discover, "_arp_table", lambda: {
        "192.168.1.50": "d8:1f:12:0a:0b:0c",
        "224.0.0.251": "01:00:5e:00:00:fb",
    })
    monkeypatch.setattr(discover, "local_cidr", lambda iface=None: None)
    monkeypatch.setattr(discover, "_self_ips", lambda: set())
    monkeypatch.setattr(discover, "_gateway_ip", lambda: None)
    monkeypatch.setattr(discover, "_reverse_dns", lambda ip: None)
    devs = discover.arp_sweep()
    ips = {d["ip"] for d in devs}
    assert "192.168.1.50" in ips
    assert "224.0.0.251" not in ips



def test_asn_org_and_geo_for_feeder_dest():
    from iotaudit.enrich import Geo, asn_org

    asn, org = asn_org("3.70.12.148")
    assert asn == 16509 and org and "Amazon" in org
    geo = Geo()
    cc = geo.country("3.70.12.148")
    assert cc in ("DE", "Germany", "de") or cc is not None  # bundled DB-IP


def test_limited_data_caps_grade():
    from iotaudit.grading import findings_for, grade
    from iotaudit.models import Destination, Device

    dev = Device(ip="192.168.0.2")
    dev.destinations["3.70.12.148"] = Destination(
        ip="3.70.12.148", ports={8883}, encrypted=True, bytes_out=50000
    )
    f = findings_for(dev)
    assert any(x.get("category") == "coverage" for x in f)
    score, letter = grade(f)
    assert letter in "CDEF" and score <= 70


def test_tuya_profile_by_mqtt_aws():
    from iotaudit.analyze import build_devices, to_dict
    from iotaudit.capture import Collector
    from iotaudit.models import Flow

    col = Collector(["192.168.0.2"])
    col.macs["192.168.0.2"] = "70:87:9e:00:00:01"
    col.flows[("192.168.0.2", "3.70.12.148", 8883, "tcp")] = Flow(
        "192.168.0.2", "3.70.12.148", 8883, "tcp", bytes=50000, packets=100, tls=True
    )
    devs = [to_dict(d) for d in build_devices(col)]
    assert len(devs) == 1
    d = devs[0]
    dest = d["destinations"][0]
    assert dest["org"] and "Amazon" in dest["org"]
    assert "MQTT-over-TLS" in dest["protocols"]
    # AWS+8883 alone must NOT lock an Imipaw/Tuya profile
    assert not d["profile"] or "IMIPAW" not in (d["profile"] or "").upper()
    assert any("possibly Tuya" in f["title"] or "MQTT" in f["title"] for f in d["findings"])
    assert d["grade"] in "CDEF"  # limited data, not A


def test_identify_oui_alone_is_generic():
    from iotaudit.identify import identify_device

    # OUI alone: no brand/model, low confidence, shows vendor
    info = identify_device("192.168.0.2", mac="70:87:9e:00:00:01")
    assert "Imipaw" not in info["looks_like"]
    assert "feeder" not in info["looks_like"].lower()
    assert info["confidence"] == "low"
    assert "OUI only" in info["looks_like"] or "IoT module" in info["looks_like"]

    # Real evidence wins and cites the source
    tuya = identify_device("192.168.0.2", mac="70:87:9e:00:00:01",
                           tuya={"192.168.0.2": {"tuya": True, "gwId": "abcdef123456"}})
    assert "Tuya device" in tuya["looks_like"] and "LAN broadcast" in tuya["looks_like"]
    assert tuya["confidence"] == "high"
    assert "Imipaw" not in tuya["looks_like"]

    # monkeypatch-free: just check role shortcuts
    apple = identify_device("192.168.0.10", mac="00:03:93:00:00:01", role="this-host")
    assert apple["looks_like"] == "This Mac / PC"



def test_arp_sendp_uses_known_macs(monkeypatch):
    """sendp must be used with Ether(dst=known_mac); never bare send() that ARP-resolves."""
    import iotaudit.arp as arp

    sent = []

    class FakePkt:
        def __init__(self, **kw):
            self.kw = kw
        def __truediv__(self, other):
            self.kw["arp"] = getattr(other, "kw", other)
            return self

    class FakeEther:
        def __init__(self, dst=None, src=None):
            self.kw = {"dst": dst, "src": src}
        def __truediv__(self, other):
            return FakePkt(ether=self.kw, arp=getattr(other, "kw", other))

    class FakeARP:
        def __init__(self, **kw):
            self.kw = kw

    def fake_sendp(pkt, iface=None, verbose=False, count=1):
        sent.append({"pkt": pkt.kw, "iface": iface})

    monkeypatch.setattr("scapy.layers.l2.Ether", FakeEther)
    monkeypatch.setattr("scapy.layers.l2.ARP", FakeARP)
    monkeypatch.setattr("scapy.sendrecv.sendp", fake_sendp)

    sp = arp.ArpSpoofer(
        "192.168.0.50", "192.168.0.1", "en0",
        target_mac="d8:1f:12:00:00:01", gateway_mac="00:09:5b:00:00:01",
        our_mac_addr="aa:bb:cc:dd:ee:ff", interval=0.05,
    )
    sp.target_mac = "d8:1f:12:00:00:01"
    sp.gateway_mac = "00:09:5b:00:00:01"
    sp._sendp(sp.target_mac, sp.target_ip, sp.target_mac, sp.gateway_ip)
    assert sent, "sendp was not called"
    assert sent[0]["iface"] == "en0"
    assert sent[0]["pkt"]["ether"]["dst"] == "d8:1f:12:00:00:01"
    assert sent[0]["pkt"]["ether"]["src"] == "aa:bb:cc:dd:ee:ff"
    assert sent[0]["pkt"]["ether"]["dst"] != "ff:ff:ff:ff:ff:ff"


def test_resolve_iface_callable():
    import iotaudit.arp as arp
    assert callable(arp.resolve_iface)
    assert callable(arp.our_mac)


def test_live_progress_and_bpf(monkeypatch):
    import iotaudit.arp as arp
    import iotaudit.capture as cap

    calls = {}

    def fake_sniff(**kw):
        calls.update(kw)

    monkeypatch.setattr("scapy.all.sniff", fake_sniff)
    monkeypatch.setattr(arp, "_quiet_scapy", lambda: None)

    col = cap.Collector(["192.168.0.50"])
    cap.live("en0", 1, col, bpf_filter="host 192.168.0.50", progress_every=1)
    assert calls.get("iface") == "en0"
    assert calls.get("filter") == "host 192.168.0.50"
    assert calls.get("store") is False



def test_entropy_and_stun_cgnat_dns():
    import os

    from iotaudit.enrich import is_cgnat
    from iotaudit.traffic import encryption_verdict, shannon_entropy

    assert shannon_entropy(os.urandom(1000)) > 7.0
    assert encryption_verdict([b"GET / HTTP/1.0\r\n\r\n"])["kind"] == "plaintext"
    assert encryption_verdict([os.urandom(800)])["kind"] == "custom-encryption"
    assert is_cgnat("100.64.0.42")
    assert not is_cgnat("8.8.8.8")


def test_feeder_scenario_findings():
    """Synthetic recreation of a cloud pet-feeder capture."""
    import os

    from iotaudit.analyze import build_devices, to_dict
    from iotaudit.capture import Collector
    from iotaudit.models import Flow

    col = Collector(["192.168.0.50"])
    col.macs["192.168.0.50"] = "d8:1f:12:00:00:01"
    col.queries["192.168.0.50"] = {"a1-us.iotbing.com"}
    col.dns["52.42.215.72"] = {"a1-us.iotbing.com"}
    specs = [
        ("52.42.215.72", 443, 17000, True, "tcp"),
        ("52.32.71.30", 8883, 12000, True, "tcp"),
        ("51.81.153.85", 3478, 4000, False, "udp"),
        ("100.64.0.42", 52265, 3000, False, "udp"),
        ("8.8.8.8", 53, 200, False, "udp"),
        ("15.204.77.209", 1443, 18000, False, "tcp"),
    ]
    for dst, port, nbytes, tls, proto in specs:
        f = Flow("192.168.0.50", dst, port, proto, bytes=nbytes, packets=max(1, nbytes // 100), tls=tls)
        if port == 1443:
            f.payload_samples = [os.urandom(400)]
        col.flows[(f.src, f.dst, f.dport, f.proto)] = f
    lf = Flow("192.168.0.50", "192.168.0.10", 7000, "udp", bytes=2_000_000, packets=2000, lan=True)
    col.lan_flows[(lf.src, lf.dst, lf.dport, lf.proto)] = lf

    d = to_dict(build_devices(col)[0])
    assert d["profile"] and "iotbing" in d["profile"].lower()
    titles = [f["title"] for f in d["findings"]]
    assert not any("possibly Tuya" in t for t in titles), titles
    assert any("STUN/TURN" in t for t in titles)
    assert any("Hardcoded public DNS" in t for t in titles)
    assert any("Carrier NAT" in t or "CGNAT" in t for t in titles)
    assert any("LAN peer" in t for t in titles)
    assert any("Non-standard encryption" in t for t in titles)
    assert not any("Traffic looks like audio+video" in t for t in titles)
    assert d["lan_peers"] and d["lan_peers"][0]["bytes_out"] == 2_000_000
    assert d["summary"]
    custom = next(x for x in d["destinations"] if x["ip"] == "15.204.77.209")
    assert custom["encryption_kind"] == "custom-encryption"


def test_soft_tuya_dropped_when_dns_present():
    from iotaudit.analyze import build_devices, to_dict
    from iotaudit.capture import Collector
    from iotaudit.models import Flow

    col = Collector(["192.168.0.2"])
    col.queries["192.168.0.2"] = {"a1-us.iotbing.com"}
    col.dns["3.70.12.148"] = {"a1-us.iotbing.com"}
    col.flows[("192.168.0.2", "3.70.12.148", 8883, "tcp")] = Flow(
        "192.168.0.2", "3.70.12.148", 8883, "tcp", bytes=5000, packets=10, tls=True
    )
    d = to_dict(build_devices(col)[0])
    assert not any("possibly Tuya" in f["title"] for f in d["findings"])



def test_stun_not_claimed_as_video_and_broadcast_split():

    from iotaudit.analyze import build_devices, to_dict
    from iotaudit.capture import Collector
    from iotaudit.models import Flow
    from iotaudit.traffic import classify_traffic

    assert classify_traffic(4000, 60, {3478}, 80, {"STUN/TURN"})["label"] == "p2p-setup"
    col = Collector(["192.168.0.50"])
    # broadcast Tuya discovery
    bf = Flow("192.168.0.50", "255.255.255.255", 6667, "udp", bytes=30000, packets=100, lan=True)
    col.lan_flows[(bf.src, bf.dst, bf.dport, bf.proto)] = bf
    # unicast to phone
    pf = Flow("192.168.0.50", "192.168.0.9", 7000, "udp", bytes=500000, packets=400, lan=True,
              bytes_in=200000, packets_in=150)
    col.lan_flows[(pf.src, pf.dst, pf.dport, pf.proto)] = pf
    # STUN only internet
    sf = Flow("192.168.0.50", "1.2.3.4", 3478, "udp", bytes=4000, packets=20)
    col.flows[(sf.src, sf.dst, sf.dport, sf.proto)] = sf
    # CGNAT with STUN-like payload
    stun = bytes([0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42]) + b"\x00" * 20
    cf = Flow("192.168.0.50", "100.64.1.2", 58872, "udp", bytes=3000, packets=10)
    cf.payload_samples = [stun]
    col.flows[(cf.src, cf.dst, cf.dport, cf.proto)] = cf

    d = to_dict(build_devices(col, peer_labels={"192.168.0.9": "Apple device (iPhone)"})[0])
    assert d["broadcasts"] and d["broadcasts"][0]["ip"] == "255.255.255.255"
    assert d["lan_peers"] and d["lan_peers"][0]["ip"] == "192.168.0.9"
    assert d["lan_peers"][0]["bytes_in"] == 200000
    assert d["lan_peers"][0].get("looks_like")
    titles = [f["title"] for f in d["findings"]]
    assert not any("audio+video" in t for t in titles)
    cgnat = next(x for x in d["destinations"] if x["ip"].startswith("100."))
    assert cgnat["encryption_kind"] == "stun"
    assert d["idle_upload"]
