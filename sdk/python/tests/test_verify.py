"""The Python library must agree with the Go server on every vector.

Three implementations agreeing with each other but not with the server is the
failure this file exists to prevent, so the vectors are produced by the
server's own signing code.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from statushub import (
    VerificationError,
    first_header,
    is_terminal,
    parse_event,
    sign,
    verify_or_raise,
    verify_signature,
)

FIXTURES = json.loads(
    (pathlib.Path(__file__).parent.parent.parent / "fixtures" / "signature_vectors.json").read_text()
)


def test_agrees_with_the_server_on_every_vector() -> None:
    assert FIXTURES["vectors"], "no vectors found"
    for v in FIXTURES["vectors"]:
        got = verify_signature(
            v["body"], v["signature_header"], v["secret"],
            tolerance_seconds=v["tolerance_seconds"], now=v["now_unix"],
        )
        assert got == v["should_pass"], f'{v["name"]}: {v["description"]}'


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("replayed", "stale"),
        ("tampered_body", "bad_signature"),
        ("wrong_secret", "bad_signature"),
        ("no_timestamp", "malformed"),
        ("no_signature", "malformed"),
        ("empty_header", "no_signature"),
    ],
)
def test_names_why_it_rejected(name: str, reason: str) -> None:
    """The reason is for your logs; the response should be a bare 401 either way."""
    v = next(x for x in FIXTURES["vectors"] if x["name"] == name)
    with pytest.raises(VerificationError) as excinfo:
        verify_or_raise(
            v["body"], v["signature_header"], v["secret"],
            tolerance_seconds=v["tolerance_seconds"], now=v["now_unix"],
        )
    assert excinfo.value.reason == reason


def test_round_trips_its_own_signatures() -> None:
    body = '{"event_id":"sh_evt_1","status":"success"}'
    header = sign(body, "a-secret", 1786511671)
    assert verify_signature(body, header, "a-secret", now=1786511671)
    assert not verify_signature(body, header, "another-secret", now=1786511671)


def test_tolerates_clock_drift_in_both_directions() -> None:
    # A receiver that only tolerates the past rejects every delivery from a
    # sender running slightly fast.
    body = '{"x":1}'
    header = sign(body, "s", 1786511671)
    assert verify_signature(body, header, "s", now=1786511671 - 120)
    assert verify_signature(body, header, "s", now=1786511671 + 120)


def test_accepts_bytes_and_str_bodies() -> None:
    # Flask hands over bytes, some frameworks hand over str, and the signature
    # must not depend on which.
    body = '{"x":1}'
    header = sign(body, "s", 1786511671)
    assert verify_signature(body, header, "s", now=1786511671)
    assert verify_signature(body.encode(), header, "s", now=1786511671)


def test_reads_headers_however_the_framework_hands_them_over() -> None:
    # Getting this wrong reads as a missing signature, which sends people
    # looking in entirely the wrong place.
    assert first_header({"X-StatusHub-Signature": "t=1,v1=a"}) == "t=1,v1=a"
    assert first_header({"x-statushub-signature": "t=1,v1=a"}) == "t=1,v1=a"
    assert first_header({"HTTP_X_STATUSHUB_SIGNATURE": "x", "x-statushub-signature": ["t=1,v1=a"]}) == "t=1,v1=a"
    assert first_header({"x-statushub-signature": b"t=1,v1=a"}) == "t=1,v1=a"
    assert first_header({"other": "x"}) is None


def test_unknown_is_not_terminal() -> None:
    # Not knowing what something is includes not knowing whether it is
    # finished. A handler treating unknown as terminal stops watching a
    # transaction that is still moving.
    assert not is_terminal("unknown")
    assert not is_terminal("pending")
    for status in ("success", "failed", "reversed", "abandoned"):
        assert is_terminal(status), status


def test_parses_the_canonical_shape() -> None:
    v = next(x for x in FIXTURES["vectors"] if x["name"] == "genuine")
    e = parse_event(v["body"])
    assert e.transaction_ref == "TXN-2026-08-11-8842"
    assert e.status == "success"
    assert e.amount_minor == 5_000_000
    assert e.currency == "NGN"
    assert e.is_terminal
