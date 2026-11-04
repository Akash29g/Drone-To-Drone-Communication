"""drone.py - The drone and the 3-message authentication protocol.

    M1  A -> B : cert_A, ephA, nA, tsA, Sig_A(M1)
    M2  B -> A : cert_B, ephB, nB, tsB, Sig_B(M1 || M2)
    M3  A -> B : HMAC(K_mac, "A-confirm" || M1 || M2)
    shared secret = X25519(ephA, ephB)  ->  keys in session.py

Uses:    gcs.py     (registration, certificate check, signature check)
         session.py (key derivation, confirmation tag, Session)
Used by: attacks.py
Run:     python drone.py
"""
import os
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from gcs import GCS, AuthError, ser, pub_hex, verify_sig, verify_certificate
from session import Session, derive_keys, make_tag, check_tag

MAX_SKEW = 30   # seconds a timestamp may differ from my clock


def dh(my_eph, peer_eph_hex: str) -> bytes:
    """X25519 Diffie-Hellman: my ephemeral private key + peer's ephemeral public key -> shared secret."""
    return my_eph.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(peer_eph_hex)))


class Drone:
    def __init__(self, drone_id: str, gcs: GCS):
        self.id = drone_id
        self._sk = Ed25519PrivateKey.generate()            # long-term signing key, never leaves the drone
        self.gcs_pk = gcs.pk                               # trust anchor
        self.crl = gcs.revoked                             # ponytail: shared set stands in for a CRL broadcast
        self.cert = gcs.register(drone_id, pub_hex(self._sk))
        self._seen_nonces = set()                          # replay cache
        self._pending = {}                                 # half-finished handshakes, keyed by peer id

    def _unsigned(self, msg: dict) -> bytes:
        """Every field except the signature itself = the bytes that get signed."""
        return ser({k: v for k, v in msg.items() if k != "sig"})

    def _check(self, msg: dict, expected_type: int, signed: bytes) -> str:
        """All checks on an incoming M1/M2. Returns sender's public key or raises AuthError."""
        if msg.get("type") != expected_type or msg.get("to") != self.id:
            raise AuthError("wrong message type or not addressed to me")
        if abs(time.time() - msg["ts"]) > MAX_SKEW:
            raise AuthError("stale timestamp")
        if msg["n"] in self._seen_nonces:
            raise AuthError("replayed nonce")
        pk = verify_certificate(msg["cert"], self.gcs_pk, self.crl, msg["from"])
        if not verify_sig(pk, msg["sig"], signed):
            raise AuthError("bad signature")
        self._seen_nonces.add(msg["n"])
        return pk

    def initiate(self, peer_id: str) -> dict:
        """A builds M1."""
        eph = X25519PrivateKey.generate()                  # fresh DH key, thrown away after this session
        m1 = {"type": 1, "from": self.id, "to": peer_id, "cert": self.cert,
              "eph": pub_hex(eph), "n": os.urandom(16).hex(), "ts": time.time()}
        m1["sig"] = self._sk.sign(self._unsigned(m1)).hex()
        self._pending[peer_id] = (eph, m1)
        return m1

    def respond(self, m1: dict) -> dict:
        """B checks M1, builds M2. Signs M1 || M2 so the reply is tied to THIS request."""
        self._check(m1, 1, self._unsigned(m1))
        eph = X25519PrivateKey.generate()
        m2 = {"type": 2, "from": self.id, "to": m1["from"], "cert": self.cert,
              "eph": pub_hex(eph), "n": os.urandom(16).hex(), "ts": time.time()}
        m2["sig"] = self._sk.sign(ser(m1) + self._unsigned(m2)).hex()
        self._pending[m1["from"]] = (eph, m1, m2)
        return m2

    def finish(self, m2: dict) -> tuple[dict, Session]:
        """A checks M2, derives keys, sends M3 to prove it has the same key."""
        eph, m1 = self._pending.pop(m2["from"])
        self._check(m2, 2, ser(m1) + self._unsigned(m2))
        k_enc, k_mac, transcript = derive_keys(dh(eph, m2["eph"]), m1, m2)
        m3 = {"type": 3, "from": self.id, "to": m2["from"], "tag": make_tag(k_mac, transcript)}
        return m3, Session(k_enc, 0, m2["from"])

    def confirm(self, m3: dict) -> Session:
        """B checks the tag in M3. Only now is the session established."""
        eph, m1, m2 = self._pending.pop(m3["from"])
        k_enc, k_mac, transcript = derive_keys(dh(eph, m1["eph"]), m1, m2)
        if not check_tag(k_mac, transcript, m3["tag"]):
            raise AuthError("key confirmation failed")
        return Session(k_enc, 1, m3["from"])


def handshake(a: Drone, b: Drone) -> tuple[Session, Session]:
    """Run M1, M2, M3 between two honest drones."""
    m1 = a.initiate(b.id)
    m2 = b.respond(m1)
    m3, sa = a.finish(m2)
    sb = b.confirm(m3)
    return sa, sb


if __name__ == "__main__":
    gcs = GCS()
    alpha, bravo = Drone("DRONE-ALPHA", gcs), Drone("DRONE-BRAVO", gcs)

    m1 = alpha.initiate(bravo.id)
    print("M1 ALPHA -> BRAVO :", list(m1))
    m2 = bravo.respond(m1)
    print("M2 BRAVO -> ALPHA :", list(m2), " (BRAVO checked ALPHA's cert + signature)")
    m3, s_alpha = alpha.finish(m2)
    print("M3 ALPHA -> BRAVO :", list(m3), " (ALPHA checked BRAVO's cert + signature)")
    s_bravo = bravo.confirm(m3)
    print("BRAVO checked the confirmation tag")
    print("\nSame session key on both drones:", s_alpha.key == s_bravo.key)
    print("BRAVO reads:", s_bravo.open(s_alpha.seal(b"hold position at 120 m")).decode())
