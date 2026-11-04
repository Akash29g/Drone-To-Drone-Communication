"""attacks.py - Security testing: each test is one attack, and it must be blocked.

ATTACK MODEL (Dolev-Yao): the attacker controls the radio channel. It can read, drop,
replay, change and inject any message, and can run its own drones or its own fake GCS.
It cannot break AES / SHA-256 / Ed25519 / X25519 and does not know honest drones' private keys.

Uses: gcs.py, drone.py, session.py (everything)
Run:  python attacks.py        or   pytest attacks.py
"""
import copy
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from gcs import GCS, AuthError, pub_hex
from drone import Drone, handshake


def setup():
    gcs = GCS()
    return gcs, Drone("A", gcs), Drone("B", gcs)


def blocked(attack, reason):
    """Run the attack. It must raise AuthError containing `reason`; otherwise the attack worked."""
    try:
        attack()
    except AuthError as e:
        assert reason in str(e), f"expected '{reason}', got '{e}'"
        return
    raise AssertionError("attack succeeded!")


def test_honest_run():
    """Baseline: two honest drones agree on a key and talk."""
    _, a, b = setup()
    sa, sb = handshake(a, b)
    assert sa.key == sb.key
    assert sb.open(sa.seal(b"hi")) == b"hi"


def test_replay_handshake():
    """Replay of a recorded M1 -> nonce cache."""
    _, a, b = setup()
    m1 = a.initiate("B")
    b.respond(m1)
    blocked(lambda: b.respond(m1), "replayed nonce")


def test_replay_data_packet():
    """Replay of a recorded 'land now' packet -> sequence counter."""
    _, a, b = setup()
    sa, sb = handshake(a, b)
    pkt = sa.seal(b"land now")
    sb.open(pkt)
    blocked(lambda: sb.open(pkt), "replayed")


def test_stale_timestamp():
    """Replay of an old handshake -> timestamp window."""
    _, a, b = setup()
    m1 = a.initiate("B")
    m1["ts"] -= 120
    blocked(lambda: b.respond(m1), "stale")


def test_mitm_swaps_dh_key():
    """MITM swaps A's DH key in M1 -> A's signature no longer matches."""
    _, a, b = setup()
    m1 = a.initiate("B")
    m1["eph"] = pub_hex(X25519PrivateKey.generate())
    blocked(lambda: b.respond(m1), "bad signature")


def test_mitm_on_response():
    """MITM swaps B's DH key in M2 -> B's signature no longer matches."""
    _, a, b = setup()
    m2 = b.respond(a.initiate("B"))
    m2["eph"] = pub_hex(X25519PrivateKey.generate())
    blocked(lambda: a.finish(m2), "bad signature")


def test_impersonation_fake_cert():
    """Rogue drone with a cert from the attacker's own GCS -> not signed by our GCS."""
    _, _, b = setup()
    rogue = Drone("A", GCS())
    blocked(lambda: b.respond(rogue.initiate("B")), "not signed by GCS")


def test_stolen_cert_without_key():
    """Attacker presents A's real cert but lacks A's private key -> bad signature."""
    gcs, a, b = setup()
    eve = Drone("EVE", gcs)
    eve.id, eve.cert = "A", a.cert
    blocked(lambda: b.respond(eve.initiate("B")), "bad signature")


def test_revoked_drone():
    """Captured drone revoked by GCS -> refused (authorization)."""
    gcs, a, b = setup()
    gcs.revoke("A")
    blocked(lambda: b.respond(a.initiate("B")), "revoked")


def test_expired_cert():
    """Editing the cert's expiry -> breaks the GCS signature."""
    _, a, b = setup()
    a.cert = copy.deepcopy(a.cert)
    a.cert["body"]["exp"] = int(time.time()) - 1
    blocked(lambda: b.respond(a.initiate("B")), "not signed by GCS")


def test_misdirected_message():
    """Message for B delivered to C -> 'to' field check."""
    gcs, a, _ = setup()
    c = Drone("C", gcs)
    blocked(lambda: c.respond(a.initiate("B")), "not addressed to me")


def test_tampered_ciphertext():
    """Flip one bit of a data packet -> AES-GCM tag fails."""
    _, a, b = setup()
    sa, sb = handshake(a, b)
    pkt = sa.seal(b"alt=120")
    ct = bytearray.fromhex(pkt["ct"])
    ct[0] ^= 1
    pkt["ct"] = ct.hex()
    blocked(lambda: sb.open(pkt), "integrity")


def test_forged_key_confirmation():
    """Fake M3 with a made-up tag -> attacker doesn't know K_mac."""
    _, a, b = setup()
    b.respond(a.initiate("B"))
    blocked(lambda: b.confirm({"type": 3, "from": "A", "to": "B", "tag": "00" * 32}), "confirmation")


def test_fresh_keys_per_session():
    """Forward secrecy: new DH keys every time -> every session key is different."""
    _, a, b = setup()
    assert handshake(a, b)[0].key != handshake(a, b)[0].key


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in globals().items() if name.startswith("test_")]
    for name, fn in tests:
        fn()
        print(f"PASS  {name:30s} {fn.__doc__}")
    print(f"\nAll {len(tests)} checks passed - every attack was blocked.")
