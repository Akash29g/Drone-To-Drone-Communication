"""gcs.py - Ground Control Station (GCS): the trusted authority.

Job:     register drones on the ground, give each one a signed certificate,
         revoke drones that get captured.
Used by: drone.py   (a Drone registers here, and checks peers with verify_certificate)
         session.py (uses AuthError and ser)
Run:     python gcs.py
"""
import json
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class AuthError(Exception):
    """Raised by every file whenever a security check fails."""


def ser(d: dict) -> bytes:
    """Dict -> bytes, always in the same order, so the signer and the verifier see identical bytes."""
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def pub_hex(private_key) -> str:
    """Public half of a key pair, as hex text (so it can sit inside a message)."""
    raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw.hex()


def verify_sig(pk_hex: str, sig_hex: str, data: bytes) -> bool:
    """True if `sig` is a valid Ed25519 signature on `data` by the owner of `pk`."""
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex)).verify(bytes.fromhex(sig_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False


class GCS:
    def __init__(self):
        self._sk = Ed25519PrivateKey.generate()   # GCS private key: signs every certificate
        self.pk = pub_hex(self._sk)               # GCS public key: pre-loaded on every drone
        self.revoked = set()                      # certificate revocation list (CRL)

    def register(self, drone_id: str, drone_pk: str, valid_secs: int = 3600) -> dict:
        """Registration phase (done on the ground). cert = {body, Sig_GCS(body)}."""
        body = {"id": drone_id, "pk": drone_pk, "exp": int(time.time()) + valid_secs}
        return {"body": body, "sig": self._sk.sign(ser(body)).hex()}

    def revoke(self, drone_id: str):
        """Drone captured -> put it on the CRL; honest drones will refuse it."""
        self.revoked.add(drone_id)


def verify_certificate(cert: dict, gcs_pk: str, crl: set, claimed_id: str) -> str:
    """Run by a drone on a peer's certificate. Returns the peer's public key, or raises AuthError."""
    if not verify_sig(gcs_pk, cert["sig"], ser(cert["body"])):
        raise AuthError("certificate not signed by GCS")
    if cert["body"]["exp"] < time.time():
        raise AuthError("certificate expired")
    if cert["body"]["id"] != claimed_id:
        raise AuthError("certificate does not match sender id")
    if claimed_id in crl:
        raise AuthError("drone revoked")
    return cert["body"]["pk"]


if __name__ == "__main__":
    gcs = GCS()
    drone_key = Ed25519PrivateKey.generate()
    cert = gcs.register("DRONE-ALPHA", pub_hex(drone_key))
    print("1. GCS issued certificate:", cert["body"])
    print("2. Verified -> accepted, pk =", verify_certificate(cert, gcs.pk, gcs.revoked, "DRONE-ALPHA")[:16], "...")

    cert["body"]["exp"] += 99999                       # attacker tries to extend the expiry
    try:
        verify_certificate(cert, gcs.pk, gcs.revoked, "DRONE-ALPHA")
    except AuthError as e:
        print("3. Attacker edits expiry          ->", e)

    fake = GCS().register("DRONE-ALPHA", pub_hex(drone_key))   # cert from an attacker-run GCS
    try:
        verify_certificate(fake, gcs.pk, gcs.revoked, "DRONE-ALPHA")
    except AuthError as e:
        print("4. Cert from a fake GCS           ->", e)

    gcs.revoke("DRONE-ALPHA")
    try:
        verify_certificate(gcs.register("DRONE-ALPHA", pub_hex(drone_key)), gcs.pk, gcs.revoked, "DRONE-ALPHA")
    except AuthError as e:
        print("5. Drone captured, GCS revokes it ->", e)
