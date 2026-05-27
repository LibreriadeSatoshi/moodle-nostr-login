"""
Security tests for auth_nostr Moodle plugin.

Run:
    pip install -r tests/requirements.txt
    pytest tests/test_security.py -v

Override the Moodle URL:
    MOODLE_URL=http://mysite pytest tests/test_security.py -v
"""

import hashlib
import json
import os
import time

import pytest
import requests

# ── Configuration ────────────────────────────────────────────────────────────

MOODLE_URL = os.getenv("MOODLE_URL", "http://localhost:8888")
LOGIN_URL  = f"{MOODLE_URL}/auth/nostr/login.php"

# ── secp256k1 / BIP340 pure-Python (no external deps) ────────────────────────

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _point_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    if P1[0] == P2[0]:
        if P1[1] != P2[1]: return None
        lam = 3 * P1[0] ** 2 * pow(2 * P1[1], _P - 2, _P) % _P
    else:
        lam = (P2[1] - P1[1]) * pow(P2[0] - P1[0], _P - 2, _P) % _P
    x = (lam * lam - P1[0] - P2[0]) % _P
    y = (lam * (P1[0] - x) - P1[1]) % _P
    return x, y


def _point_mul(P, n):
    R = None
    while n:
        if n & 1: R = _point_add(R, P)
        P = _point_add(P, P)
        n >>= 1
    return R


def _tagged_hash(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _schnorr_sign(msg: bytes, seckey: bytes) -> bytes:
    d0 = int.from_bytes(seckey, "big")
    P  = _point_mul(_G, d0)
    d  = d0 if P[1] % 2 == 0 else _N - d0
    t  = d ^ int.from_bytes(_tagged_hash("BIP0340/aux", b"\x00" * 32), "big")
    k0 = int.from_bytes(
        _tagged_hash("BIP0340/nonce", t.to_bytes(32, "big") + P[0].to_bytes(32, "big") + msg),
        "big",
    ) % _N
    R  = _point_mul(_G, k0)
    k  = k0 if R[1] % 2 == 0 else _N - k0
    e  = int.from_bytes(
        _tagged_hash("BIP0340/challenge", R[0].to_bytes(32, "big") + P[0].to_bytes(32, "big") + msg),
        "big",
    ) % _N
    return R[0].to_bytes(32, "big") + ((k + e * d) % _N).to_bytes(32, "big")


def _pubkey_from_seckey(seckey: bytes) -> str:
    P = _point_mul(_G, int.from_bytes(seckey, "big"))
    return P[0].to_bytes(32, "big").hex()


# ── Nostr event helpers ───────────────────────────────────────────────────────

# Fixed test key — deterministic, never used outside tests
_SECKEY = bytes.fromhex("b94f5374fce5edbc8e2a8697c15331677e6ebf0b000000000000000000000001")
_PUBKEY = _pubkey_from_seckey(_SECKEY)


def _event_id(event: dict) -> str:
    payload = json.dumps(
        [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _make_event(
    nonce: str,
    url: str,
    *,
    seckey: bytes = _SECKEY,
    pubkey: str   = _PUBKEY,
    kind: int     = 27235,
    method: str   = "POST",
    time_offset: int = 0,
) -> dict:
    event = {
        "pubkey":     pubkey,
        "created_at": int(time.time()) + time_offset,
        "kind":       kind,
        "tags":       [["u", url], ["method", method], ["challenge", nonce]],
        "content":    "",
    }
    event["id"]  = _event_id(event)
    event["sig"] = _schnorr_sign(bytes.fromhex(event["id"]), seckey).hex()
    return event


def _challenge(session: requests.Session):
    r = session.get(LOGIN_URL, params={"action": "challenge"})
    assert r.status_code == 200, f"Challenge failed: {r.text}"
    d = r.json()
    return d["nonce"], d["url"]


def _login(session: requests.Session, event: dict, metadata=None):
    return session.post(LOGIN_URL, json={"event": event, "metadata": metadata})


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestHappyPath:
    def test_valid_login_returns_redirect(self):
        s = requests.Session()
        nonce, url = _challenge(s)
        r = _login(s, _make_event(nonce, url))
        assert r.status_code == 200
        assert "redirect" in r.json()

    def test_valid_login_with_metadata(self):
        s = requests.Session()
        nonce, url = _challenge(s)
        r = _login(s, _make_event(nonce, url), metadata={"display_name": "Test User"})
        assert r.status_code == 200
        assert "redirect" in r.json()


class TestReplayProtection:
    def test_nonce_consumed_after_login(self):
        """Same signed event cannot be replayed after a successful login."""
        s = requests.Session()
        nonce, url = _challenge(s)
        event = _make_event(nonce, url)
        _login(s, event)
        r = _login(s, event)  # replay
        assert r.status_code == 400

    def test_expired_event_rejected(self):
        s = requests.Session()
        nonce, url = _challenge(s)
        r = _login(s, _make_event(nonce, url, time_offset=-120))
        assert r.status_code == 400

    def test_future_event_rejected(self):
        s = requests.Session()
        nonce, url = _challenge(s)
        r = _login(s, _make_event(nonce, url, time_offset=120))
        assert r.status_code == 400


class TestSignatureVerification:
    def test_zeroed_signature_rejected(self):
        s = requests.Session()
        nonce, url = _challenge(s)
        event = _make_event(nonce, url)
        event["sig"] = "00" * 64
        r = _login(s, event)
        assert r.status_code == 401

    def test_tampered_event_id_rejected(self):
        """Replacing the event ID without re-signing should fail."""
        s = requests.Session()
        nonce, url = _challenge(s)
        event = _make_event(nonce, url)
        event["id"] = "ff" * 32
        r = _login(s, event)
        assert r.status_code == 401

    def test_wrong_pubkey_rejected(self):
        """Claiming a different pubkey than the one that signed the event."""
        s = requests.Session()
        nonce, url = _challenge(s)
        event = _make_event(nonce, url)
        event["pubkey"] = "aa" * 32
        event["id"] = _event_id(event)  # recompute ID with fake pubkey; sig is still for original
        r = _login(s, event)
        assert r.status_code == 401

    def test_signature_from_different_key_rejected(self):
        """Valid signature but from a key that doesn't match the claimed pubkey."""
        other_seckey = bytes.fromhex(
            "c94f5374fce5edbc8e2a8697c15331677e6ebf0b000000000000000000000002"
        )
        s = requests.Session()
        nonce, url = _challenge(s)
        # Sign with other_seckey but present _PUBKEY
        event = _make_event(nonce, url, seckey=other_seckey, pubkey=_PUBKEY)
        r = _login(s, event)
        assert r.status_code == 401


class TestProtocolChecks:
    def test_post_without_prior_challenge_rejected(self):
        """POST with no GET challenge first — session has no nonce."""
        s = requests.Session()
        event = _make_event("fake_nonce", LOGIN_URL)
        r = _login(s, event)
        assert r.status_code == 400

    def test_wrong_nonce_rejected(self):
        s = requests.Session()
        _challenge(s)  # real nonce stored in session
        event = _make_event("wrong_nonce_value", LOGIN_URL)
        r = _login(s, event)
        assert r.status_code == 400

    def test_wrong_url_tag_rejected(self):
        s = requests.Session()
        nonce, _ = _challenge(s)
        r = _login(s, _make_event(nonce, "https://evil.com/steal"))
        assert r.status_code == 400

    def test_wrong_method_tag_rejected(self):
        s = requests.Session()
        nonce, url = _challenge(s)
        r = _login(s, _make_event(nonce, url, method="GET"))
        assert r.status_code == 400

    def test_wrong_kind_rejected(self):
        s = requests.Session()
        nonce, url = _challenge(s)
        r = _login(s, _make_event(nonce, url, kind=1))
        assert r.status_code == 400

    def test_get_on_post_endpoint_rejected(self):
        r = requests.get(LOGIN_URL)  # no ?action=challenge
        assert r.status_code == 405


class TestInputValidation:
    def test_empty_body_rejected(self):
        s = requests.Session()
        r = s.post(LOGIN_URL, data="", headers={"Content-Type": "application/json"})
        assert r.status_code == 400

    def test_non_json_body_rejected(self):
        s = requests.Session()
        r = s.post(LOGIN_URL, data="not json", headers={"Content-Type": "application/json"})
        assert r.status_code == 400

    def test_missing_event_field_rejected(self):
        s = requests.Session()
        r = s.post(LOGIN_URL, json={"metadata": {}})
        assert r.status_code == 400

    def test_missing_sig_in_event_rejected(self):
        s = requests.Session()
        nonce, url = _challenge(s)
        event = _make_event(nonce, url)
        del event["sig"]
        r = _login(s, event)
        assert r.status_code in (400, 401)

    def test_missing_id_in_event_rejected(self):
        s = requests.Session()
        nonce, url = _challenge(s)
        event = _make_event(nonce, url)
        del event["id"]
        r = _login(s, event)
        assert r.status_code in (400, 401)
