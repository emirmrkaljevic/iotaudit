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
