"""MQTT publish of the Home Assistant summary (no live broker required)."""

from __future__ import annotations

import json
import socket
import struct
import threading
from argparse import Namespace
from datetime import datetime, timezone

import pytest

from iotaudit.ha import (
    device_unique_id,
    ha_mqtt_messages,
    ha_summary,
    publish_ha_mqtt,
    publish_ha_summary,
    topic_slug,
)
from iotaudit.mqttpub import (
    MqttError,
    connect_packet,
    disconnect_packet,
    parse_mqtt_target,
    publish_many,
    publish_packet,
)

RFC1918 = "192.0.2.10"  # actually TEST-NET-1; used as a device IP
RFC1918_B = "192.0.2.20"
MAC = "02:00:00:00:00:0a"


def _read_packet(sock: socket.socket) -> tuple[int, bytes]:
    header = sock.recv(1)
    if not header:
        return 0, b""
    length = 0
    multiplier = 1
    while True:
        byte = sock.recv(1)
        if not byte:
            raise OSError("short MQTT length")
        length += (byte[0] & 0x7F) * multiplier
        if not (byte[0] & 0x80):
            break
        multiplier *= 128
    body = b""
    while len(body) < length:
        piece = sock.recv(length - len(body))
        if not piece:
            raise OSError("short MQTT body")
        body += piece
    return header[0], body


def _decode_publish(header: int, body: bytes) -> tuple[str, bytes, bool]:
    tlen = struct.unpack("!H", body[:2])[0]
    topic = body[2 : 2 + tlen].decode("utf-8")
    rest = body[2 + tlen :]
    qos = (header >> 1) & 0x03
    if qos:
        rest = rest[2:]
    return topic, rest, bool(header & 0x01)


class FakeBroker:
    def __init__(self, connack: int = 0):
        self.connack = connack
        self.messages: list[tuple[str, bytes, bool]] = []
        self.connect_flags = None
        self.client_id = None
        self.username = None
        self.password = None
        self.error = None
        self.ready = threading.Event()
        self.done = threading.Event()
        self.port = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> FakeBroker:
        self._thread.start()
        assert self.ready.wait(3), "fake broker did not start"
        return self

    def _run(self) -> None:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        self.port = srv.getsockname()[1]
        srv.listen(1)
        srv.settimeout(6)
        self.ready.set()
        conn = None
        try:
            conn, _ = srv.accept()
            conn.settimeout(6)
            header, body = _read_packet(conn)
            assert (header & 0xF0) == 0x10
            proto_len = struct.unpack("!H", body[:2])[0]
            i = 2 + proto_len  # skip "MQTT"
            i += 1  # level
            self.connect_flags = body[i]
            i += 3  # flags + keepalive
            cid_len = struct.unpack("!H", body[i : i + 2])[0]
            i += 2
            self.client_id = body[i : i + cid_len].decode()
            i += cid_len
            if self.connect_flags & 0x80:
                ulen = struct.unpack("!H", body[i : i + 2])[0]
                i += 2
                self.username = body[i : i + ulen].decode()
                i += ulen
            if self.connect_flags & 0x40:
                plen = struct.unpack("!H", body[i : i + 2])[0]
                i += 2
                self.password = body[i : i + plen].decode()
            conn.sendall(b"\x20\x02\x00" + bytes([self.connack]))
            if self.connack != 0:
                return
            while True:
                header, body = _read_packet(conn)
                if header == 0:
                    break
                if (header & 0xF0) == 0xE0:
                    break
                if (header & 0xF0) == 0x30:
                    self.messages.append(_decode_publish(header, body))
        except Exception as exc:  # noqa: BLE001 - test helper records any accept/read error
            self.error = exc
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass
            srv.close()
            self.done.set()


def _sample_summary() -> dict:
    devices = [
        {
            "ip": RFC1918,
            "mac": MAC,
            "looks_like": "bulb",
            "grade": "D",
            "grade_reasons": ["hardcoded DNS"],
            "findings": ["Uses 8.8.8.8 instead of your router DNS"],
            "destinations": [],
            "scan": {},
        },
        {
            "ip": RFC1918_B,
            "mac": "02:00:00:00:00:0b",
            "looks_like": "Speaker-2",
            "grade": "A",
            "grade_reasons": [],
            "findings": [],
            "destinations": [],
            "scan": {},
        },
    ]
    return ha_summary(devices, None, now=datetime(2026, 1, 2, 12, 0, tzinfo=timezone.utc))


def test_parse_mqtt_target_host_and_url(monkeypatch):
    monkeypatch.delenv("IOTAUDIT_MQTT_PASSWORD", raising=False)
    monkeypatch.delenv("IOTAUDIT_MQTT_USER", raising=False)
    monkeypatch.delenv("IOTAUDIT_MQTT_USERNAME", raising=False)
    plain = parse_mqtt_target("192.0.2.1")
    assert plain == {
        "host": "192.0.2.1",
        "port": 1883,
        "tls": False,
        "username": None,
        "password": None,
    }
    tls = parse_mqtt_target("mqtts://broker.example:8883")
    assert tls["host"] == "broker.example"
    assert tls["port"] == 8883
    assert tls["tls"] is True
    auth = parse_mqtt_target("mqtt://user:p%40ss@127.0.0.1:1884")
    assert auth["username"] == "user"
    assert auth["password"] == "p@ss"
    assert auth["port"] == 1884
    monkeypatch.setenv("IOTAUDIT_MQTT_PASSWORD", "secret")
    monkeypatch.setenv("IOTAUDIT_MQTT_USER", "ha")
    env = parse_mqtt_target("127.0.0.1")
    assert env["username"] == "ha"
    assert env["password"] == "secret"
    with pytest.raises(ValueError):
        parse_mqtt_target("")
    with pytest.raises(ValueError):
        parse_mqtt_target("http://127.0.0.1")


def test_connect_and_publish_packets_roundtrip():
    raw = connect_packet("iotaudit-1", "user", "pass", keepalive=60)
    assert raw[0] == 0x10
    assert b"MQTT" in raw
    pub = publish_packet("iotaudit/worst_grade", "D", retain=True)
    assert pub[0] == 0x31
    assert b"iotaudit/worst_grade" in pub
    assert pub.endswith(b"D")
    assert disconnect_packet() == b"\xe0\x00"
    with pytest.raises(ValueError):
        connect_packet("cid", password="x")


def test_topic_slug_and_unique_id():
    assert topic_slug("Speaker-2") == "speaker_2"
    assert topic_slug("192.0.2.10") == "192_0_2_10"
    uid = device_unique_id({"name": "bulb", "ip": RFC1918}, 0)
    assert uid == "iotaudit_bulb_192_0_2_10"
    assert device_unique_id({"name": RFC1918, "ip": RFC1918}, 0) == "iotaudit_192_0_2_10"


def test_ha_mqtt_messages_discovery_and_state():
    summary = _sample_summary()
    messages = ha_mqtt_messages(summary, version="0.1.20")
    topics = [t for t, _, _ in messages]
    payloads = {t: p for t, p, _ in messages}
    assert all(retain for _, _, retain in messages)
    assert "iotaudit/summary" in topics
    assert "iotaudit/worst_grade" in topics
    assert "iotaudit/changed" in topics
    assert payloads["iotaudit/worst_grade"] == "D"
    assert payloads["iotaudit/changed"] == "0"
    assert payloads["iotaudit/security_relevant"] == "false"
    assert payloads["iotaudit/generated"] == "2026-01-02T12:00:00+00:00"
    body = json.loads(payloads["iotaudit/summary"])
    assert body["worst_grade"] == "D"
    assert body["devices"] == 2
    assert "device_list" in body
    assert "iotaudit/availability" in topics
    assert payloads["iotaudit/availability"] == "online"
    cfg = json.loads(payloads["homeassistant/sensor/iotaudit_worst_grade/config"])
    assert cfg["state_topic"] == "iotaudit/worst_grade"
    assert cfg["unique_id"] == "iotaudit_worst_grade"
    assert cfg["device"]["identifiers"] == ["iotaudit"]
    assert cfg["device"]["sw_version"] == "0.1.20"
    change = json.loads(payloads["homeassistant/binary_sensor/iotaudit_changed/config"])
    assert change["state_topic"] == "iotaudit/security_relevant"
    assert change["payload_on"] == "true"
    uid = "iotaudit_bulb_192_0_2_10"
    assert payloads[f"iotaudit/device/{uid}/grade"] == "D"
    state = json.loads(payloads[f"iotaudit/device/{uid}/state"])
    assert state["ip"] == RFC1918
    assert state["name"] == "bulb"
    disc = json.loads(payloads[f"homeassistant/sensor/{uid}/config"])
    assert disc["json_attributes_topic"] == f"iotaudit/device/{uid}/state"
    bare = ha_mqtt_messages(summary, discovery=False)
    assert all(not t.startswith("homeassistant/") for t, _, _ in bare)
    blob = json.dumps(payloads)
    assert RFC1918 in blob
    assert "02:00:00:00:00:0a" not in blob  # MAC is not in the HA summary
    assert "\u2014" not in blob and "\u2013" not in blob
    assert "—" not in blob and "–" not in blob


def test_publish_many_against_fake_broker():
    broker = FakeBroker().start()
    summary = _sample_summary()
    count = publish_ha_summary(summary, f"127.0.0.1:{broker.port}", discovery=True)
    assert broker.done.wait(4)
    assert broker.error is None
    assert count == len(broker.messages)
    topics = {t for t, _, _ in broker.messages}
    assert "iotaudit/worst_grade" in topics
    grades = [p for t, p, r in broker.messages if t == "iotaudit/worst_grade"]
    assert grades == [b"D"]
    assert all(retain for _, _, retain in broker.messages)


def test_broker_rejection_and_refused_connect():
    broker = FakeBroker(connack=5).start()
    with pytest.raises(MqttError, match="refused"):
        publish_many(
            {"host": "127.0.0.1", "port": broker.port, "tls": False, "username": None, "password": None},
            [("iotaudit/test", "x", False)],
        )
    assert broker.done.wait(4)
    with pytest.raises((OSError, MqttError, TimeoutError)):
        publish_many(
            {"host": "127.0.0.1", "port": 1, "tls": False, "username": None, "password": None},
            [("iotaudit/test", "x", False)],
            timeout=0.4,
        )


def test_publish_ha_mqtt_cli_wrapper(tmp_path, capsys):
    broker = FakeBroker().start()
    args = Namespace(
        ha_mqtt=f"127.0.0.1:{broker.port}",
        ha_mqtt_topic="iotaudit",
        ha_mqtt_discovery=True,
        ha_mqtt_user=None,
    )
    rc = publish_ha_mqtt(_sample_summary(), args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "Published" in out
    assert f"mqtt://127.0.0.1:{broker.port}" in out
    assert broker.done.wait(4)
    bad = publish_ha_mqtt(
        _sample_summary(),
        Namespace(
            ha_mqtt="127.0.0.1:1",
            ha_mqtt_topic="iotaudit",
            ha_mqtt_discovery=False,
            ha_mqtt_user=None,
        ),
    )
    assert bad == 1
    err = capsys.readouterr().err
    assert "MQTT publish failed" in err
    assert publish_ha_mqtt(_sample_summary(), Namespace(ha_mqtt=None)) == 0


def test_export_cli_publishes_mqtt(tmp_path, capsys):
    from iotaudit.cli import main

    audit = {
        "iotaudit": "0.1.20",
        "devices": [
            {
                "ip": RFC1918,
                "mac": MAC,
                "name": "bulb",
                "grade": "D",
                "grade_reasons": ["hardcoded DNS"],
                "findings": ["Uses 8.8.8.8 instead of your router DNS"],
                "destinations": [],
                "scan": {},
            }
        ],
    }
    path = tmp_path / "audit.json"
    path.write_text(json.dumps(audit), encoding="utf-8")
    broker = FakeBroker().start()
    rc = main(
        [
            "export",
            str(path),
            "--ha-mqtt",
            f"127.0.0.1:{broker.port}",
            "--no-ha-mqtt-discovery",
        ]
    )
    assert rc == 0
    assert broker.done.wait(4)
    assert broker.error is None
    topics = {t for t, _, _ in broker.messages}
    assert "iotaudit/worst_grade" in topics
    assert "iotaudit/summary" in topics
    assert not any(t.startswith("homeassistant/") for t in topics)
    out = capsys.readouterr().out
    assert "Published" in out
    # MQTT-only export should not dump the JSON to stdout
    assert "worst_grade" not in out or "Published" in out
    assert "{\n" not in out
