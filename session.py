"""session.py - Keys and the encrypted channel (used after the handshake).

Job:     turn the Diffie-Hellman secret into keys, make/check the key-confirmation tag,
         then encrypt + authenticate every data packet and block replays.
Uses:    gcs.py   (AuthError, ser)
Used by: drone.py (calls derive_keys, make_tag, check_tag, and creates a Session)
Run:     python session.py
"""
import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag
from gcs import AuthError, ser


def derive_keys(dh_secret: bytes, m1: dict, m2: dict) -> tuple[bytes, bytes, bytes]:
    """DH secret -> (K_enc, K_mac, transcript) using HKDF-SHA256."""
    salt = bytes.fromhex(m1["n"]) + bytes.fromhex(m2["n"])     # both fresh nonces -> new keys every session
    info = f"{m1['from']}|{m1['to']}".encode()                  # binds keys to these two drones
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=info).derive(dh_secret)
    transcript = ser(m1) + ser(m2)                              # everything both sides saw
    return okm[:32], okm[32:], transcript                       # K_enc (AES), K_mac (HMAC)


def make_tag(k_mac: bytes, transcript: bytes) -> str:
    """Key-confirmation tag = HMAC-SHA256(K_mac, "A-confirm" || transcript)."""
    h = hmac.HMAC(k_mac, hashes.SHA256())
    h.update(b"A-confirm" + transcript)
    return h.finalize().hex()


def check_tag(k_mac: bytes, transcript: bytes, tag_hex: str) -> bool:
    h = hmac.HMAC(k_mac, hashes.SHA256())
    h.update(b"A-confirm" + transcript)
    try:
        h.verify(bytes.fromhex(tag_hex))     # constant-time compare (no timing leak)
        return True
    except (InvalidSignature, ValueError):
        return False


class Session:
    """Secure channel. role 0 = initiator, 1 = responder."""

    def __init__(self, key: bytes, role: int, peer: str):
        self.key, self.role, self.peer = key, role, peer
        self.send_seq = 0      # my outgoing message counter
        self.recv_seq = -1     # highest counter I have accepted so far

    def seal(self, plaintext: bytes) -> dict:
        """Encrypt + authenticate one packet with AES-256-GCM."""
        self.send_seq += 1
        nonce = bytes([self.role]) + self.send_seq.to_bytes(11, "big")   # 12 bytes, never repeats
        aad = str(self.send_seq).encode()                                 # counter is authenticated, not secret
        return {"seq": self.send_seq, "ct": AESGCM(self.key).encrypt(nonce, plaintext, aad).hex()}

    def open(self, msg: dict) -> bytes:
        """Check counter, then decrypt. Any change to ciphertext or counter -> rejected."""
        seq = msg["seq"]
        if seq <= self.recv_seq:
            raise AuthError("replayed/old message")
        nonce = bytes([1 - self.role]) + seq.to_bytes(11, "big")         # the peer's direction
        try:
            pt = AESGCM(self.key).decrypt(nonce, bytes.fromhex(msg["ct"]), str(seq).encode())
        except (InvalidTag, ValueError):
            raise AuthError("integrity check failed (tampered ciphertext)")
        self.recv_seq = seq                                               # advance only after it verified
        return pt


if __name__ == "__main__":
    key = os.urandom(32)            # normally comes from the handshake in drone.py
    alpha, bravo = Session(key, 0, "BRAVO"), Session(key, 1, "ALPHA")

    pkt = alpha.seal(b'{"lat":17.98,"lon":79.53,"alt":120}')
    print("1. ALPHA sends (ciphertext):", pkt["ct"][:40], "...")
    print("2. BRAVO decrypts          :", bravo.open(pkt).decode())
    try:
        bravo.open(pkt)
    except AuthError as e:
        print("3. Attacker replays packet  ->", e)

    pkt2 = alpha.seal(b"alt=120")
    ct = bytearray.fromhex(pkt2["ct"])
    ct[0] ^= 1                      # flip one bit
    pkt2["ct"] = ct.hex()
    try:
        bravo.open(pkt2)
    except AuthError as e:
        print("4. Attacker flips one bit   ->", e)
