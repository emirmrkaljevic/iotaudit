"""UPnP IGD port-forward audit against a fake router on 127.0.0.1 (read-only actions only)."""

from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from iotaudit import upnp
from iotaudit.report import render_html

SVC = "urn:schemas-upnp-org:service:WANIPConnection:1"
DESC = f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<friendlyName>Home Router</friendlyName><modelName>HR-1</modelName>
<deviceList><device><deviceList><device><serviceList><service>
<serviceType>{SVC}</serviceType><controlURL>/ctl/IPConn</controlURL>
</service></serviceList></device></deviceList></device></deviceList></device></root>"""
MAPPINGS = [
    ("554", "TCP", "192.168.0.50", "554", "Camera <script>alert(1)</script>"),
    ("40001", "UDP", "192.168.0.50", "40001", "P2P"),
    ("8443", "TCP", "192.168.0.9", "443", "NAS"),
]
FAULT = """<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>
<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>713</errorCode>
<errorDescription>SpecifiedArrayIndexInvalid</errorDescription></UPnPError></detail></s:Fault>
</s:Body></s:Envelope>"""


def _ok(action, fields):
    inner = "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
    return (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<s:Body><u:{action}Response xmlns:u="{SVC}">{inner}</u:{action}Response></s:Body>'
            f'</s:Envelope>')


class FakeIGD(BaseHTTPRequestHandler):
    actions: list = []

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):  # noqa: N802
        self._send(200, DESC)

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        action = self.headers["SOAPAction"].strip('"').split("#")[1]
        FakeIGD.actions.append(action)
        if action == "GetExternalIPAddress":
            return self._send(200, _ok(action, {"NewExternalIPAddress": "203.0.113.7"}))
        i = int(re.search(r"<NewPortMappingIndex>(\d+)<", body).group(1))
        if i >= len(MAPPINGS):
            return self._send(500, FAULT)
        ext, proto, client, port, desc = MAPPINGS[i]
        desc = desc.replace("<", "&lt;").replace(">", "&gt;")
        return self._send(200, _ok(action, {
            "NewRemoteHost": "", "NewExternalPort": ext, "NewProtocol": proto,
            "NewInternalPort": port, "NewInternalClient": client, "NewEnabled": "1",
            "NewPortMappingDescription": desc, "NewLeaseDuration": "0"}))


@pytest.fixture()
def router():
    FakeIGD.actions = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeIGD)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/rootDesc.xml"
    srv.shutdown()
    srv.server_close()


def test_audit_lists_mappings_read_only(router):
    u = upnp.audit(locations=[router])
    assert not u["errors"]
    r = u["routers"][0]
    assert r["name"] == "Home Router" and r["external_ip"] == "203.0.113.7"
    assert r["control_url"].endswith("/ctl/IPConn")
    assert [m["external_port"] for m in u["mappings"]] == [554, 40001, 8443]
    assert set(FakeIGD.actions) <= upnp.READ_ONLY_ACTIONS


def test_device_findings(router):
    u = upnp.audit(locations=[router])
    f = upnp.findings_for_device("192.168.0.50", u)
    assert len(f) == 2
    rtsp = f[0]
    assert rtsp["severity"] == "high" and "RTSP" in rtsp["title"] and rtsp["category"] == "upnp"
    assert f[1]["severity"] == "medium"
    assert upnp.findings_for_device("192.168.0.77", u) == []
    assert upnp.findings_for_device("192.168.0.50", None) == []


def test_report_escapes_network_supplied_text(router):
    u = upnp.audit(locations=[router])
    f = upnp.findings_for_device("192.168.0.50", u)
    html = render_html([{"ip": "192.168.0.50", "findings": f, "destinations": [], "lan_peers": [],
                         "open_ports": [], "dns_queries": [], "broadcasts": [], "bursts": [],
                         "series_total": {}, "grade": "D", "score": 50}], {"upnp": "x"})
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html


def test_write_actions_are_refused():
    with pytest.raises(ValueError):
        upnp.soap("http://127.0.0.1:1/ctl", SVC, "AddPortMapping", {})
    with pytest.raises(ValueError):
        upnp.soap("http://127.0.0.1:1/ctl", SVC, "DeletePortMapping", {})


def test_non_local_urls_refused():
    assert not upnp._local_url("http://8.8.8.8/desc.xml")
    assert not upnp._local_url("http://evil.example.com/desc.xml")
    assert not upnp._local_url("file:///etc/passwd")
    assert upnp._local_url("http://192.168.1.1:5000/rootDesc.xml")
    u = upnp.audit(locations=["http://8.8.8.8/rootDesc.xml"])
    assert u["routers"] == [] and "refusing" in u["errors"][0]


def test_parse_fault_and_no_wan_service():
    assert upnp.parse_soap_response(FAULT.encode(), 500) == {"fault": "713"}
    d = upnp.parse_description(b"<root><device><friendlyName>x</friendlyName></device></root>",
                               "http://192.168.1.1/")
    assert d["control_url"] is None and d["name"] == "x"


def test_cli_upnp_and_capture_default():
    from iotaudit.cli import build_parser

    p = build_parser()
    assert p.parse_args(["upnp"]).func.__name__ == "cmd_upnp"
    assert p.parse_args(["capture", "--i-own-this-network"]).upnp is True
    assert p.parse_args(["capture", "--no-upnp"]).upnp is False
    assert p.parse_args(["analyze", "x.pcap"]).upnp is False
