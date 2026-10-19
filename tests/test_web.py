"""Local web UI: token/host/origin guards, LAN client policy, pcap upload, scan/capture jobs."""

from __future__ import annotations

import http.client
import json
import threading
import time
import uuid

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from iotaudit.web import client_allowed, host_allowed, make_server, safe_upload_name


@pytest.fixture()
def server(tmp_path):
    calls = {}

    def fake_scan():
        with srv.jobs.lock:
            srv.jobs.scan["devices"] = [{"ip": "192.168.0.50", "vendor": "Tuya Smart", "looks_like": "x"}]

    def fake_capture(ip, duration, out):
        calls["capture"] = (ip, duration)
        out.write_text("<html>cap</html>")
        with srv.jobs.lock:
            srv.jobs.capture["report"] = out.name

    srv = make_server("127.0.0.1", 0, token="tok123", reports_dir=tmp_path,
                      scan_fn=fake_scan, capture_fn=fake_capture)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    srv.calls = calls
    yield srv
    srv.shutdown()
    srv.server_close()


def req(srv, method, path, body=None, headers=None, host=None):
    port = srv.server_address[1]
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": host or f"127.0.0.1:{port}"}
    h.update(headers or {})
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read()
    return r.status, dict(r.getheaders()), data


AUTH = {"X-Iotaudit-Token": "tok123"}


def test_requires_token(server):
    assert req(server, "GET", "/")[0] == 401
    assert req(server, "GET", "/", headers={"X-Iotaudit-Token": "wrong"})[0] == 401
    assert req(server, "GET", "/", headers=AUTH)[0] == 200


def test_token_query_sets_cookie_and_redirects(server):
    status, headers, _ = req(server, "GET", "/?token=tok123")
    assert status == 303
    cookie = headers.get("Set-Cookie", "")
    assert "iotaudit_token=tok123" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert req(server, "GET", "/", headers={"Cookie": "iotaudit_token=tok123"})[0] == 200


def test_dns_rebinding_host_rejected(server):
    assert req(server, "GET", "/", headers=AUTH, host="evil.example.com")[0] == 421


def test_cross_origin_post_rejected(server):
    s, _, _ = req(server, "POST", "/scan", body=b"",
                  headers={**AUTH, "Origin": "https://evil.example.com"})
    assert s == 403


def test_policy_helpers():
    assert host_allowed("localhost:8765", set())
    assert host_allowed("[::1]:8765", {"::1"})
    assert not host_allowed("attacker.test:8765", {"127.0.0.1"})
    assert client_allowed("127.0.0.1", lan=False)
    assert not client_allowed("192.168.0.9", lan=False)
    assert client_allowed("192.168.0.9", lan=True)
    assert not client_allowed("8.8.8.8", lan=True)
    assert safe_upload_name("../../etc/passwd") == "passwd.pcap"
    assert safe_upload_name("PCAPdroid_19_Oct.pcap") == "PCAPdroid_19_Oct.pcap"


def _multipart(fields):
    b = uuid.uuid4().hex
    parts = []
    for name, (fname, data) in fields.items():
        disp = f'form-data; name="{name}"' + (f'; filename="{fname}"' if fname else "")
        parts.append(f"--{b}\r\nContent-Disposition: {disp}\r\n\r\n".encode() + data + b"\r\n")
    return b"".join(parts) + f"--{b}--\r\n".encode(), f"multipart/form-data; boundary={b}"


def test_upload_pcap_creates_report(server, tmp_path):
    pcap = tmp_path / "in.pcap"
    wrpcap(str(pcap), [Ether() / IP(src="10.215.173.1", dst="8.8.8.8") / UDP(dport=53) / b"q"] * 3)
    body, ctype = _multipart({"pcap": ("PCAPdroid.pcap", pcap.read_bytes()), "device": (None, b"")})
    s, h, _ = req(server, "POST", "/upload", body=body, headers={**AUTH, "Content-Type": ctype})
    assert s == 303 and h["Location"].startswith("/report/upload-")
    s, h, page = req(server, "GET", h["Location"], headers=AUTH)
    assert s == 200 and b"iotaudit report" in page
    assert "default-src 'none'" in h.get("Content-Security-Policy", "")
    assert b"upload-" in req(server, "GET", "/", headers=AUTH)[2]


def test_report_path_traversal_blocked(server):
    assert req(server, "GET", "/report/..%2F..%2Fetc%2Fpasswd", headers=AUTH)[0] == 404
    assert req(server, "GET", "/report/../x.html", headers=AUTH)[0] == 404


def test_scan_then_capture_requires_consent(server):
    assert req(server, "POST", "/scan", body=b"", headers=AUTH)[0] == 303
    for _ in range(50):
        st = json.loads(req(server, "GET", "/api/status", headers=AUTH)[2])
        if st["scan"]["state"] == "done":
            break
        time.sleep(0.05)
    assert st["scan"]["devices"][0]["ip"] == "192.168.0.50"
    form = {"Content-Type": "application/x-www-form-urlencoded", **AUTH}
    assert req(server, "POST", "/capture", body=b"device=192.168.0.50&duration=120",
               headers=form)[0] == 400
    assert req(server, "POST", "/capture", body=b"device=8.8.8.8&duration=120&consent=yes",
               headers=form)[0] == 400
    assert req(server, "POST", "/capture", body=b"device=192.168.0.50&duration=120&consent=yes",
               headers=form)[0] == 303
    for _ in range(50):
        st = json.loads(req(server, "GET", "/api/status", headers=AUTH)[2])
        if st["capture"]["state"] == "done":
            break
        time.sleep(0.05)
    assert server.calls["capture"] == ("192.168.0.50", 120)
    assert st["capture"]["report"].startswith("capture-")


def test_cli_has_web_subcommand():
    from iotaudit.cli import build_parser

    a = build_parser().parse_args(["web", "--lan", "--port", "9999"])
    assert a.lan and a.port == 9999 and a.func.__name__ == "cmd_web"


def test_page_escapes_network_supplied_names(server):
    page = req(server, "GET", "/", headers=AUTH)[2].decode()
    assert "function e(v)" in page and "e(d.vendor)" in page and "e(d.looks_like)" in page
