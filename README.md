# Secure Drone-to-Drone Authentication Protocol

**CS428 Design of Secure Protocols · NIT Warangal · Project Title 6**
*"Design a secure protocol for authentication between drone-to-drone communication."*

Two drones that have never met prove their identities to each other and agree on a fresh secret key, with no server contact during flight. Then they exchange telemetry over an encrypted, tamper-proof channel.

> **New here? Read [docs/0_START_HERE.md](docs/0_START_HERE.md) first.** It explains the whole project end to end in simple words.

## Run

```bash
pip install -r requirements.txt
python gcs.py        # Person 1 demo: certificates
python drone.py      # Person 2 demo: the handshake
python session.py    # Person 3 demo: encrypted channel
python attacks.py    # Person 4 demo: 14 security checks, all pass
```

## Files, one per person

| File | Person | What it does | Study doc |
|---|---|---|---|
| `gcs.py` | 1 | Ground station: registers drones, signs certificates, revokes captured drones | [docs/1_gcs.md](docs/1_gcs.md) |
| `drone.py` | 2 | The protocol: messages M1 → M2 → M3, all security checks | [docs/2_drone.md](docs/2_drone.md) |
| `session.py` | 3 | Key derivation (HKDF), key confirmation (HMAC), encrypted channel (AES-GCM) | [docs/3_session.md](docs/3_session.md) |
| `attacks.py` | 4 | Attack model + 13 attacks, each must be blocked | [docs/4_attacks.md](docs/4_attacks.md) |

**Presentation order:** 1 → 2 → 3 → 4, about 3 minutes each. Each person opens their own file and runs `python <file>.py`.

## How the files link

```
gcs.py          base file, imports none of ours
  ▲   ▲
  │   └──────────── session.py      uses AuthError, ser
  │                    ▲
  │                    │ derive_keys, make_tag, check_tag, Session
drone.py ──────────────┘            uses GCS, verify_certificate, verify_sig, pub_hex
  ▲
  │ Drone, handshake
attacks.py                          uses everything
```

Flow in one sentence: **`gcs.py`** gives each drone a certificate → **`drone.py`** uses it to authenticate and run Diffie-Hellman → **`session.py`** turns the DH secret into keys and encrypts traffic → **`attacks.py`** tries to break all of it.

## The protocol

```
Registration (on the ground):  cert_D = Sig_GCS(ID_D, pk_D, expiry)

M1  A -> B : cert_A, ephA, nA, tsA, Sig_A(M1)
M2  B -> A : cert_B, ephB, nB, tsB, Sig_B(M1 || M2)
M3  A -> B : HMAC(K_mac, "A-confirm" || M1 || M2)

(K_enc, K_mac) = HKDF-SHA256( X25519(ephA, ephB), salt = nA||nB, info = A|B )
Data packets:  AES-256-GCM, nonce = role || counter
```

## Answers to the four points in the project brief

**1. Entities:** the Ground Control Station (trusted authority, offline during flight), the drones (peers), and the attacker (controls the radio channel).

**2. Authentication parameters:** drone ID + Ed25519 key pair, bound by a GCS-signed certificate with an expiry, and the GCS public key pre-loaded as the trust anchor. Freshness comes from 128-bit nonces + timestamps.

**3. Services provided:**

| Service | Mechanism | File |
|---|---|---|
| Mutual authentication | Ed25519 signatures + GCS certificates | `gcs.py`, `drone.py` |
| Authorization | Certificate expiry + revocation list | `gcs.py` |
| Confidentiality | AES-256-GCM | `session.py` |
| Integrity | GCM tag, HMAC key confirmation | `session.py` |
| Non-repudiation | Signed handshake messages | `drone.py` |
| Anti-replay | Nonces, timestamps, sequence numbers | `drone.py`, `session.py` |
| Forward secrecy | Ephemeral X25519 Diffie-Hellman | `drone.py` |

**4. Security testing:** Dolev-Yao attack model, with 13 attacks plus 1 honest baseline in `attacks.py` (replay, MITM, impersonation, stolen certificate, revoked or expired drones, tampering, forged confirmation). All are blocked.

## Lecture-plan topics used

Digital Signature Schemes · Secure Authenticated Key exchange protocols · CDH/DDH, Discrete logarithm problem · SSL/TLS session establishment, cipher suites · Authenticated Encryption · CCA-Secure Encryption · CPA-Security · Modes of Operation · Message Authentication Using Hash Functions · Merkle–Damgård · Random-Oracle Model (CDH-based KEM) · Types of Attacks (COA, KPA, CPA, CCA) · Application area: Vehicular Network. Each person's doc shows exactly where each one appears.

## Limitations / future work

- **Group key for a whole swarm.** Lecture topic: Secure Group Key agreement protocols.
- **GCS key split across servers.** Lecture topic: Secret Sharing and Threshold Encryption.
- **Formal verification** with ProVerif or Tamarin.
- **Sliding replay window** for radio links that reorder packets.
