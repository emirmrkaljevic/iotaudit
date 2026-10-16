"""Consent gate. iotaudit only works on networks and devices you own or administer."""

from __future__ import annotations

import sys

CONSENT_TEXT = """\
iotaudit captures network traffic and scans devices.

Only use it on a network you own or administer, and only against devices you
own or have explicit permission to test. Intercepting or scanning third-party
networks or devices is illegal in most countries (e.g. EU Directive 2013/40/EU).
All captured data stays on this computer; nothing is uploaded.
"""

PHRASE = "I OWN THIS NETWORK"


def require_consent(assume_yes: bool = False, stream_in=None, stream_out=None) -> bool:
    """Return True if the user confirmed. `assume_yes` is for scripted use (--i-own-this-network)."""
    out = stream_out or sys.stderr
    if assume_yes:
        print("Consent given via --i-own-this-network.", file=out)
        return True
    inp = stream_in or sys.stdin
    print(CONSENT_TEXT, file=out)
    print(f'Type "{PHRASE}" to continue: ', end="", file=out, flush=True)
    answer = inp.readline().strip()
    return answer.upper() == PHRASE
