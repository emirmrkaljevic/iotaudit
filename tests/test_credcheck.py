"""Opt-in default-credential check: confirmation gate, LAN-only, rate limit, accepted/not-accepted."""

from __future__ import annotations

import pytest

from iotaudit import credcheck as cc
from iotaudit.cli import build_parser


def make_factory(accept_on=None, calls=None, raise_err=None):
    """Return an attempt_factory whose attempt() accepts only the (user,pwd) in accept_on."""
    def factory(host, port, timeout):
        def attempt(user, pwd):
            if calls is not None:
                calls.append((user, pwd))
            if raise_err:
                raise raise_err
            return (user, pwd) == accept_on
        return attempt
    return factory


def test_requires_confirmation():
    with pytest.raises(PermissionError):
        cc.check_device("192.168.0.50", ["telnet"], confirmed=False)


def test_non_lan_refused():
    with pytest.raises(ValueError):
        cc.check_device("8.8.8.8", ["telnet"], confirmed=True)
    r = cc.check_service("1.2.3.4", "telnet")
    assert not r.accepted and "not a private" in r.error
    assert not cc.is_lan_target("8.8.8.8")
    assert cc.is_lan_target("192.168.0.50") and cc.is_lan_target("127.0.0.1")


def test_accepted_default_login_stops_early():
    calls = []
    r = cc.check_service("192.168.0.50", "telnet", delay=0,
                         attempt_factory=make_factory(("root", ""), calls))
    assert r.accepted and r.username == "root"
    assert len(calls) == 1  # first default in the list, stops immediately
    f = r.as_finding()
    assert f["severity"] == "high" and f["category"] == "credential"
    assert "root" in f["evidence"]["username"]


def test_not_accepted_tries_full_list_then_reports_clean():
    calls = []
    r = cc.check_service("192.168.0.50", "telnet", delay=0,
                         attempt_factory=make_factory(("nope", "nope"), calls))
    assert not r.accepted and r.attempts == len(cc.TELNET_DEFAULTS)
    assert len(calls) == len(cc.TELNET_DEFAULTS)
    f = r.as_finding()
    assert f["severity"] == "info" and "No default" in f["title"]


def test_rate_limited_between_attempts(monkeypatch):
    slept = []
    monkeypatch.setattr(cc.time, "sleep", lambda s: slept.append(s))
    cc.check_service("192.168.0.50", "telnet", delay=1.0,
                     attempt_factory=make_factory(("nope", "nope")))
    # one sleep between each of the N attempts (N-1 sleeps), all using the configured delay
    assert slept and len(slept) == len(cc.TELNET_DEFAULTS) - 1 and all(s == 1.0 for s in slept)


def test_attempt_cap_never_exceeds_max():
    cc_list = [("u", str(i), "x") for i in range(50)]
    calls = []

    def factory(host, port, timeout):
        def attempt(user, pwd):
            calls.append(pwd)
            return False
        return attempt
    r = cc._try_each("telnet", 23, cc_list, factory("h", 23, 1)
                     if False else factory("h", 23, 1), delay=0)
    assert r.attempts == cc.MAX_ATTEMPTS and len(calls) == cc.MAX_ATTEMPTS


def test_connection_error_reported_not_raised():
    r = cc.check_service("192.168.0.50", "telnet", delay=0,
                         attempt_factory=make_factory(raise_err=OSError("refused")))
    assert not r.accepted and "refused" in r.error
    f = r.as_finding()
    assert f["severity"] == "info" and "could not run" in f["title"]


def test_multiple_services():
    res = cc.check_device("192.168.0.50", ["telnet", "http"], confirmed=True, delay=0,
                          attempt_factories={
                              "telnet": make_factory(("admin", "admin")),
                              "http": make_factory(("nope", "nope")),
                          })
    assert res[0].service == "telnet" and res[0].accepted
    assert res[1].service == "http" and not res[1].accepted


def test_cli_parses_and_refuses_public(capsys):
    p = build_parser()
    a = p.parse_args(["credcheck", "10.0.0.5", "--service", "telnet", "--service", "ftp", "--yes"])
    assert a.func.__name__ == "cmd_credcheck" and a.service == ["telnet", "ftp"] and a.yes
    rc = a.func(p.parse_args(["credcheck", "8.8.8.8", "--yes"]))
    assert rc == 2 and "not a private" in capsys.readouterr().err
