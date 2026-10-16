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
    assert d["vendor"] == "Tuya Smart" and "Tuya" in d["profile"]
    dests = {x["ip"]: x for x in d["destinations"]}
    assert dests["3.120.1.1"]["encrypted"] and dests["3.120.1.1"]["expected"]
    assert not dests["47.1.2.3"]["encrypted"] and dests["47.1.2.3"]["tracker"]
    assert d["grade"] in "CDEF"
    assert all(f["confidence"] == "certain" and f["category"] for f in d["findings"])
    html = render_html(devs)
    assert "tuyaeu.com" in html and DEV in html


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
    assert {"analyze_pcap", "capture", "scan_device"} <= names


def test_arp_safety_and_forwarding():
    import iotaudit.arp as arp

    # refuses public IPs
    try:
        arp.ArpSpoofer("8.8.8.8", "192.168.1.1")
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
        {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Ubiquiti", "hostname": "router"},
        {"ip": "192.168.1.50", "mac": "d8:1f:12:00:00:01", "vendor": "Tuya Smart", "hostname": None},
    ]
    t = format_table(devs)
    assert "likely IoT" in t and "192.168.1.50" in t
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
    assert mac_vendor("0:1a:2b:3:4:5") is None  # unknown, but must not raise
    assert mac_vendor("2:0:0:0:0:1") == "Randomized MAC"  # LAA bit
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
