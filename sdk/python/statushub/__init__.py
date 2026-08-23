"""StatusHub client library.

Deliberately small. The integration StatusHub sells is a URL change, so this
library's job is not to be a framework: it is to make the one piece of code
you *do* have to write impossible to get wrong.

That piece is signature verification. It is the most commonly botched part of
any webhook integration — somebody compares two hex strings with ``==``, which
in CPython short-circuits on the first differing byte, and an attacker who can
measure that can forge a signature a byte at a time. Nobody notices, because
the handler works perfectly.

Apache-2.0, so integrating needs no lawyer.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

__all__ = [
    "SIGNATURE_HEADER",
    "DEFAULT_TOLERANCE_SECONDS",
    "VerificationError",
    "verify_signature",
    "verify_or_raise",
    "sign",
    "parse_event",
    "is_terminal",
    "Event",
    "Customer",
]

#: The header StatusHub signs deliveries with.
SIGNATURE_HEADER = "X-StatusHub-Signature"

#: Headers StatusHub sets on every delivery.
EVENT_ID_HEADER = "X-StatusHub-Event-Id"
REPLAY_HEADER = "X-StatusHub-Replay"
SCHEMA_VERSION_HEADER = "X-StatusHub-Schema-Version"
IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"

#: How far a delivery's timestamp may be from now, in seconds.
#:
#: Five minutes each way. Symmetric, because clocks drift in both directions
#: and a receiver that only tolerates the past rejects every delivery from a
#: sender running slightly fast.
DEFAULT_TOLERANCE_SECONDS = 300


class VerificationError(Exception):
    """Why a signature was rejected.

    The reason is for your logs. The response to the caller should be a bare
    401 either way: telling them which part of their signature was wrong turns
    your endpoint into an oracle they can tune against.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def verify_signature(
    body: bytes | str,
    header: str | None,
    secret: str,
    *,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: float | None = None,
) -> bool:
    """Verify a delivery's signature, returning ``True`` or ``False``.

    Pass the **raw** request body, before any JSON parsing. A round trip
    through a parser changes the bytes — reordered keys, different whitespace,
    numbers reformatted — and the signature covers the bytes that were sent.
    In Flask that means ``request.get_data()``, not ``request.json``.
    """
    try:
        verify_or_raise(
            body, header, secret, tolerance_seconds=tolerance_seconds, now=now
        )
    except VerificationError:
        return False
    return True


def verify_or_raise(
    body: bytes | str,
    header: str | None,
    secret: str,
    *,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: float | None = None,
) -> None:
    """Verify, raising :class:`VerificationError` with the reason."""
    if not header or not header.strip():
        raise VerificationError("no_signature", "no signature header")

    timestamp = 0
    signatures: list[str] = []
    for part in header.split(","):
        key, sep, value = part.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError as exc:
                raise VerificationError(
                    "malformed", f'timestamp "{value}" is not an integer'
                ) from exc
        elif key == "v1" and value:
            signatures.append(value)
        # Unknown elements are ignored rather than rejected. StatusHub may add
        # one, and a handler that refuses an unfamiliar element stops working
        # the day it does.

    if timestamp == 0:
        raise VerificationError("malformed", "no timestamp in the header")
    if not signatures:
        raise VerificationError("malformed", "no v1 signature in the header")

    # Checked before the digest. A captured delivery replayed tomorrow carries
    # a genuine signature; only the window stops it.
    current = time.time() if now is None else now
    drift = abs(int(current) - timestamp)
    if drift > tolerance_seconds:
        raise VerificationError("stale", f"signature is {drift}s away from now")

    raw = body.encode("utf-8") if isinstance(body, str) else body
    # The separator matters: without it, timestamp 1754903662 with body "x"
    # and timestamp 175490366 with body "2x" sign identically.
    payload = f"{timestamp}.".encode("utf-8") + raw
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    # Several v1 values appear during a secret rotation, and any one matching
    # is enough — that is what lets you rotate on your own schedule.
    for candidate in signatures:
        # compare_digest, never ==. This is the line the whole module exists
        # for.
        if hmac.compare_digest(candidate.strip().lower(), expected):
            return
    raise VerificationError("bad_signature", "no signature in the header matched the body")


def sign(body: bytes | str, secret: str, at_unix: int | None = None) -> str:
    """Sign a body.

    Exported for your own tests: it is how you build a request your handler
    will accept, without needing StatusHub running.
    """
    timestamp = int(time.time()) if at_unix is None else at_unix
    raw = body.encode("utf-8") if isinstance(body, str) else body
    payload = f"{timestamp}.".encode("utf-8") + raw
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


#: The canonical outcome. A closed set of six.
#:
#: ``unknown`` means StatusHub did not recognise the provider's value and
#: refused to guess. Handle it explicitly: the tempting shortcut is to treat
#: it as a failure, which is exactly the mistake it exists to prevent — an
#: unmapped SUCCESS treated as a failure reverses a payment that completed.
STATUSES = ("pending", "success", "failed", "reversed", "abandoned", "unknown")


def is_terminal(status: str) -> bool:
    """Whether a transaction can still change.

    ``unknown`` is not terminal: not knowing what something is includes not
    knowing whether it is finished.
    """
    return status not in ("pending", "unknown")


@dataclass(frozen=True)
class Customer:
    """Pseudonymised identity.

    There is no name, email or phone here and there never will be. The hash is
    enough to correlate two events as one person without StatusHub holding who
    that person is.
    """

    ref_hash: str = ""


@dataclass
class Event:
    """The canonical event. One shape, whichever provider sent it."""

    event_id: str = ""
    event_type: str = ""
    provider: str = ""
    provider_event_id: str = ""
    transaction_ref: str = ""
    status: str = "unknown"

    #: Always integer minor units, in the currency's own exponent — kobo for
    #: NGN, cents for USD, yen for JPY. Never a float, never a decimal string,
    #: never a unit you have to look up.
    amount_minor: int = 0
    currency: str = ""

    occurred_at: str = ""
    received_at: str = ""

    customer: Customer | None = None

    #: Every field StatusHub did not map, so you are never blocked waiting for
    #: them to add one.
    provider_extra: dict[str, Any] = field(default_factory=dict)

    #: False when StatusHub was unsure about a field. Worth branching on.
    mapping_complete: bool = True

    unmapped_status: str = ""
    redacted: bool = False
    raw: Any = None

    @property
    def is_terminal(self) -> bool:
        return is_terminal(self.status)


def parse_event(body: bytes | str) -> Event:
    """Parse a delivery body into an :class:`Event`."""
    data: Mapping[str, Any] = json.loads(body)
    customer = data.get("customer")
    return Event(
        event_id=data.get("event_id", ""),
        event_type=data.get("event_type", ""),
        provider=data.get("provider", ""),
        provider_event_id=data.get("provider_event_id", ""),
        transaction_ref=data.get("transaction_ref", ""),
        status=data.get("status", "unknown"),
        amount_minor=int(data.get("amount_minor", 0)),
        currency=data.get("currency", ""),
        occurred_at=data.get("occurred_at", ""),
        received_at=data.get("received_at", ""),
        customer=Customer(ref_hash=customer.get("ref_hash", "")) if customer else None,
        provider_extra=dict(data.get("provider_extra") or {}),
        mapping_complete=bool(data.get("mapping_complete", True)),
        unmapped_status=data.get("unmapped_status", ""),
        redacted=bool(data.get("redacted", False)),
        raw=data.get("raw"),
    )


def first_header(headers: Mapping[str, Any], *names: str) -> str | None:
    """Read a header case-insensitively, accepting the shapes frameworks use.

    Flask, Django and FastAPI each hand headers over differently, and a value
    can arrive as a list. Getting this wrong reads as a missing signature,
    which sends people looking in entirely the wrong place.
    """
    lowered = {str(k).lower(): v for k, v in headers.items()}
    for name in names or (SIGNATURE_HEADER,):
        value = lowered.get(name.lower())
        if value is None:
            continue
        if isinstance(value, (list, tuple)) and value:
            return str(value[0])
        if isinstance(value, (str, bytes)):
            return value.decode() if isinstance(value, bytes) else value
    return None
