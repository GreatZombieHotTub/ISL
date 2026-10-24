"""SAMPLE TYPE 1: BALLOT / FREQUENCY TEMPLATE (self-contained after assembly).

Install in Colab: !pip install pycryptodome cryptography
Run: python sample_type_1_frequency.py

EXAM EDIT MAP: change the choices below, then change the two input labels
inside client_submit() if your question uses different details.

Example: ID B001, detail 1 candidate=1, detail 2 constituency=101.
The numeric task is a FREQUENCY: encrypt one 1/0 per category, add them.

Copying between the two files: Steps 0–4 have the SAME function names.
Only STEP 5 (client/server) and STEP 6 (numeric task/menus) differ.
No sockets: client/server here are roles within a single menu program.
"""

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

# ===================== EDIT THESE EXAM CHOICES =====================
AES_BITS = 256             # OPTIONS: 128, 192, 256. Key bytes: 16, 24, 32.
AES_MODE = "CBC"           # OPTIONS: "ECB", "CBC", "CTR", "GCM".
HASH_METHOD = "SHA512"    # OPTIONS: "MD5", "SHA256", "SHA512".
SIGN_METHOD = "ELGAMAL"   # OPTIONS: "ELGAMAL", "RSA-PSS", "SCHNORR".
WRAP_METHOD = "RSA-OAEP"  # OPTIONS: "RSA-OAEP", "ELGAMAL", "ECC-ECDH", "SHARED".
RSA_BITS = 4096            # OPTIONS: 2048, 4096. For sample 1 choose 4096.
CATEGORIES = (1, 2, 3)    # Change if the exam has different candidate IDs.
FIXED_SAMPLE = False      # True only for sample AES-256-CBC / Paillier printouts.

# FIXED_SAMPLE gives B001/B002 the IVs, AES key and Paillier r in the paper.
# It works with AES_BITS=256, AES_MODE="CBC", WRAP_METHOD="RSA-OAEP".
SAMPLE_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
SAMPLE_IVS = {
    "B001": bytes.fromhex("202122232425262728292a2b2c2d2e2f"),
    "B002": bytes.fromhex("303132333435363738393a3b3c3d3e3f"),
}
SAMPLE_R = {"B001": 2, "B002": 3}
# ================================================================

"""Shared STEP 0–4 blocks. These are copied into BOTH final standalone files."""

import hashlib
import hmac
import json
import math
import os
import secrets
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import MD5, SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime


# ============================================================================
# STEP 0. KEYS: public locks/verifies; private unlocks/signs.
# This helper returns plain Python values so the grant file can save them.
# If your question says RSA-4096, set RSA_BITS=4096 in the choices above.
# If it says RSA-2048, set RSA_BITS=2048. RSA is generated ONCE per run.
# ============================================================================
EL_P, EL_G = 467, 2                 # Lab 3/6 ElGamal example: TOY values.
SN_P, SN_Q, SN_G = 23, 11, 4       # Lab 6 Schnorr example: TOY values.


def make_paillier_keys():
    # Fixed small values reproduce the voting sample's n=3127, g=3128.
    if FIXED_SAMPLE:
        p, q = 53, 59
    else:
        while True:
            p, q = getPrime(256), getPrime(256)
            if p != q and math.gcd(math.lcm(p - 1, q - 1), p*q) == 1:
                break
    n = p * q
    lam = math.lcm(p - 1, q - 1)
    mu = pow(lam, -1, n)            # g = n+1, so L(g^lambda)=lambda mod n.
    return (n, n + 1), (lam, mu)


def make_all_keys():
    print(f"Generating RSA-{RSA_BITS} and Paillier keys; please wait...")
    rsa = RSA.generate(RSA_BITS)
    paillier_public, paillier_private = make_paillier_keys()
    return {
        "rsa_private": rsa.export_key().decode(),
        "el_private": secrets.randbelow(EL_P - 2) + 1,
        "sn_private": secrets.randbelow(SN_Q - 1) + 1,
        "paillier_public": paillier_public,
        "paillier_private": paillier_private,
        "shared_aes_key": get_random_bytes(AES_BITS // 8).hex(),
        "index_key": get_random_bytes(32).hex(),
        "index_aes_key": get_random_bytes(16).hex(),
        # ECC recipient key is made lazily if ECC-ECDH is actually selected.
        "ec_private_int": None,
    }


def activate_keys(saved):
    global rsa_private, rsa_public, el_private, el_public, sn_private, sn_public
    global paillier_public, paillier_private, shared_aes_key
    global index_key, index_aes_key, ec_private
    rsa_private = RSA.import_key(saved["rsa_private"])
    rsa_public = rsa_private.publickey()
    el_private = int(saved["el_private"])
    el_public = pow(EL_G, el_private, EL_P)
    sn_private = int(saved["sn_private"])
    sn_public = pow(SN_G, sn_private, SN_P)
    paillier_public = tuple(saved["paillier_public"])
    paillier_private = tuple(saved["paillier_private"])
    shared_aes_key = bytes.fromhex(saved["shared_aes_key"])
    index_key = bytes.fromhex(saved["index_key"])
    index_aes_key = bytes.fromhex(saved["index_aes_key"])
    ec_private = None
    if WRAP_METHOD == "ECC-ECDH":
        from cryptography.hazmat.primitives.asymmetric import ec
        if saved["ec_private_int"] is None:
            ec_private = ec.generate_private_key(ec.SECP256R1())
            saved["ec_private_int"] = ec_private.private_numbers().private_value
        else:
            ec_private = ec.derive_private_key(int(saved["ec_private_int"]), ec.SECP256R1())


# ============================================================================
# STEP 1. HASH + SIGNATURE OPTIONS (Labs 5 + 6).
# Choose HASH_METHOD: "MD5", "SHA256", "SHA512".
# Choose SIGN_METHOD: "RSA-PSS", "ELGAMAL", "SCHNORR".
# Swap these TWO choice lines at the top; the rest of the program follows.
# MD5 and the classroom ElGamal/Schnorr parameters are for exam questions.
# ============================================================================
HASH_FUNCTIONS = {"MD5": MD5, "SHA256": SHA256, "SHA512": SHA512}


def new_hash(data):
    return HASH_FUNCTIONS[HASH_METHOD].new(data)


def sign_digest(digest):
    if SIGN_METHOD == "RSA-PSS":
        # Signature is made with RSA PRIVATE key; digest is a hash object.
        return {"scheme": SIGN_METHOD, "value": pss.new(rsa_private).sign(digest).hex()}
    if SIGN_METHOD == "ELGAMAL":
        # Same (r,s) equations as Lab 6. p=467 is only an exam-sized example.
        h = int.from_bytes(digest.digest(), "big") % (EL_P - 1)
        while True:
            k = secrets.randbelow(EL_P - 2) + 1
            if math.gcd(k, EL_P - 1) == 1:
                break
        r = pow(EL_G, k, EL_P)
        s = ((h - el_private*r) * pow(k, -1, EL_P - 1)) % (EL_P - 1)
        return {"scheme": SIGN_METHOD, "r": r, "s": s}
    if SIGN_METHOD == "SCHNORR":
        k = secrets.randbelow(SN_Q - 1) + 1
        r = pow(SN_G, k, SN_P)
        r_bytes = r.to_bytes((r.bit_length() + 7)//8, "big")
        challenge = int.from_bytes(new_hash(digest.digest() + r_bytes).digest(), "big") % SN_Q
        return {"scheme": SIGN_METHOD, "e": challenge,
                "s": (k + sn_private*challenge) % SN_Q}
    raise ValueError("Choose a supported SIGN_METHOD")


def signature_valid(digest, signature):
    try:
        if signature["scheme"] != SIGN_METHOD:
            return False
        if SIGN_METHOD == "RSA-PSS":
            pss.new(rsa_public).verify(digest, bytes.fromhex(signature["value"]))
            return True
        if SIGN_METHOD == "ELGAMAL":
            r, s = int(signature["r"]), int(signature["s"])
            if not (0 < r < EL_P and 0 <= s < EL_P - 1):
                return False
            h = int.from_bytes(digest.digest(), "big") % (EL_P - 1)
            return pow(EL_G, h, EL_P) == (pow(el_public, r, EL_P) * pow(r, s, EL_P)) % EL_P
        if SIGN_METHOD == "SCHNORR":
            e, s = int(signature["e"]), int(signature["s"])
            if not (0 <= e < SN_Q and 0 <= s < SN_Q):
                return False
            r = pow(SN_G, s, SN_P) * pow(pow(sn_public, e, SN_P), -1, SN_P) % SN_P
            r_bytes = r.to_bytes((r.bit_length() + 7)//8, "big")
            e_check = int.from_bytes(new_hash(digest.digest() + r_bytes).digest(), "big") % SN_Q
            return e == e_check
    except (ValueError, TypeError, KeyError, OverflowError):
        return False
    return False


# ============================================================================
# STEP 2A. AES OPTIONS (Lab 2).
# AES_BITS=128/192/256 means 16/24/32-BYTE KEY. Block size always 16 bytes.
# AES_MODE="ECB"/"CBC"/"CTR"/"GCM". CBC/ECB pad; CTR/GCM do not.
# IV/nonce/tag travel alongside ciphertext. GCM also checks authenticity.
# If fixed IVs are requested for cross-checking, use the CBC option only.
# ============================================================================
def aes_encrypt(data, key, chosen_iv=None):
    if len(key) != AES_BITS//8:
        raise ValueError("AES key size does not match AES_BITS")
    if AES_MODE == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return {"mode": AES_MODE, "ciphertext": cipher.encrypt(pad(data, 16)).hex()}
    if AES_MODE == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv=chosen_iv)
        return {"mode": AES_MODE, "iv": cipher.iv.hex(),
                "ciphertext": cipher.encrypt(pad(data, 16)).hex()}
    if AES_MODE == "CTR":
        cipher = AES.new(key, AES.MODE_CTR)
        return {"mode": AES_MODE, "nonce": cipher.nonce.hex(),
                "ciphertext": cipher.encrypt(data).hex()}
    if AES_MODE == "GCM":
        cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return {"mode": AES_MODE, "nonce": cipher.nonce.hex(),
                "ciphertext": ciphertext.hex(), "tag": tag.hex()}
    raise ValueError("Choose ECB, CBC, CTR, or GCM")


def aes_decrypt(packet, key):
    data = bytes.fromhex(packet["ciphertext"])
    if packet["mode"] == "ECB":
        return unpad(AES.new(key, AES.MODE_ECB).decrypt(data), 16)
    if packet["mode"] == "CBC":
        iv = bytes.fromhex(packet["iv"])
        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), 16)
    if packet["mode"] == "CTR":
        return AES.new(key, AES.MODE_CTR, nonce=bytes.fromhex(packet["nonce"])).decrypt(data)
    if packet["mode"] == "GCM":
        cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(packet["nonce"]))
        return cipher.decrypt_and_verify(data, bytes.fromhex(packet["tag"]))
    raise ValueError("Invalid stored AES mode")


# ============================================================================
# STEP 2B. AES KEY DELIVERY OPTIONS (Lab 3).
# "RSA-OAEP": RSA public encrypts AES key; RSA private opens it (2048/4096).
# "ELGAMAL": encrypt each AES key byte using the Lab 3 ElGamal equations.
# "ECC-ECDH": ephemeral ECDH + HKDF + AES-GCM (requires cryptography).
# "SHARED": no wrap; use the stored shared AES key (grant sample default).
# This is KEY DELIVERY, separate from SIGN_METHOD above.
# ============================================================================
def wrap_key(key):
    if WRAP_METHOD == "SHARED":
        if key != shared_aes_key:
            raise ValueError("SHARED must use the saved AES key")
        return {"method": "SHARED"}
    if WRAP_METHOD == "RSA-OAEP":
        return {"method": WRAP_METHOD,
                "value": PKCS1_OAEP.new(rsa_public).encrypt(key).hex()}
    if WRAP_METHOD == "ELGAMAL":
        pairs = []
        for byte in key:
            k = secrets.randbelow(EL_P - 2) + 1
            pairs.append([pow(EL_G, k, EL_P), (byte * pow(el_public, k, EL_P)) % EL_P])
        return {"method": WRAP_METHOD, "pairs": pairs}
    if WRAP_METHOD == "ECC-ECDH":
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        ephemeral = ec.generate_private_key(ec.SECP256R1())
        secret = ephemeral.exchange(ec.ECDH(), ec_private.public_key())
        kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b"exam AES key delivery").derive(secret)
        nonce = get_random_bytes(12)
        pub = ephemeral.public_key().public_bytes(serialization.Encoding.X962,
                                                   serialization.PublicFormat.UncompressedPoint)
        return {"method": WRAP_METHOD, "ephemeral": pub.hex(), "nonce": nonce.hex(),
                "value": AESGCM(kek).encrypt(nonce, key, None).hex()}
    raise ValueError("Choose a supported WRAP_METHOD")


def unwrap_key(packet):
    method = packet["method"]
    if method != WRAP_METHOD:
        raise ValueError("Stored key method differs from selected choice")
    if method == "SHARED":
        return shared_aes_key
    if method == "RSA-OAEP":
        return PKCS1_OAEP.new(rsa_private).decrypt(bytes.fromhex(packet["value"]))
    if method == "ELGAMAL":
        result = []
        for c1, c2 in packet["pairs"]:
            shared = pow(int(c1), el_private, EL_P)
            result.append(int(c2) * pow(shared, -1, EL_P) % EL_P)
        return bytes(result)
    if method == "ECC-ECDH":
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(packet["ephemeral"]))
        secret = ec_private.exchange(ec.ECDH(), ephemeral_pub)
        kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b"exam AES key delivery").derive(secret)
        return AESGCM(kek).decrypt(bytes.fromhex(packet["nonce"]),
                                    bytes.fromhex(packet["value"]), None)
    raise ValueError("Invalid stored key method")


# ============================================================================
# STEP 3. ENCRYPT A NUMBER AND OPERATE ON IT (Lab 7).
# PAiLLIER ADDITION: use these 3 functions for candidate COUNTS or money SUMS.
# For a PRODUCT question ONLY, alternatives rsa_product_* / elgamal_product_*
# are below. Do not paste product functions into an addition question!
# ============================================================================
def paillier_encrypt(number, chosen_r=None):
    n, g = paillier_public
    if not 0 <= number < n:
        raise ValueError("Paillier plaintext must be smaller than n")
    if chosen_r is None:
        while True:
            r = secrets.randbelow(n - 1) + 1
            if math.gcd(r, n) == 1:
                break
    else:
        r = chosen_r
        if not (1 <= r < n and math.gcd(r, n) == 1):
            raise ValueError("Paillier r must be coprime to n")
    return (pow(g, number, n*n) * pow(r, n, n*n)) % (n*n)


def paillier_add(ciphertexts):
    n, _ = paillier_public
    result = 1
    for ciphertext in ciphertexts:
        result = result * ciphertext % (n*n)
    return result


def paillier_decrypt(combined):
    # Call only AFTER combining ciphertexts: never open an individual amount.
    n, _ = paillier_public
    lam, mu = paillier_private
    return (((pow(combined, lam, n*n) - 1) // n) * mu) % n


# Alternative A for PRODUCT tasks: textbook RSA multiplication (toy, no OAEP).
# This is NOT RSA-OAEP key wrapping and NOT suitable for secure data storage.
def rsa_product_encrypt(number):
    if not 0 <= number < rsa_public.n:
        raise ValueError("RSA number must be smaller than n")
    return pow(number, rsa_public.e, rsa_public.n)


def rsa_product_combine(ciphertexts):
    result = 1
    for ciphertext in ciphertexts:
        result = result * ciphertext % rsa_public.n
    return result


def rsa_product_decrypt(combined):
    return pow(combined, rsa_private.d, rsa_private.n)


# Alternative B for PRODUCT tasks: Lab 7 ElGamal (toy p=467).
def elgamal_product_encrypt(number):
    if not 0 <= number < EL_P:
        raise ValueError("ElGamal number must be smaller than p")
    k = secrets.randbelow(EL_P - 2) + 1
    return (pow(EL_G, k, EL_P), number*pow(el_public, k, EL_P) % EL_P)


def elgamal_product_combine(ciphertexts):
    a, b = 1, 1
    for c1, c2 in ciphertexts:
        a, b = a*c1 % EL_P, b*c2 % EL_P
    return a, b


def elgamal_product_decrypt(combined):
    c1, c2 = combined
    return c2 * pow(pow(c1, el_private, EL_P), -1, EL_P) % EL_P


# ============================================================================
# STEP 4. SEARCH INDEX (Lab 8).
# Search text -> secret HMAC token -> AES-encrypted list of matching IDs.
# A search reads this index, not the AES-encrypted ballot/description.
# ============================================================================
def search_token(term):
    return hmac.new(index_key, term.upper().encode(), hashlib.sha256).hexdigest()


def add_to_index(term, record_id):
    cipher = AES.new(index_aes_key, AES.MODE_CBC)
    encrypted_id = cipher.encrypt(pad(record_id.encode(), 16))
    search_index.setdefault(search_token(term), []).append((cipher.iv.hex(), encrypted_id.hex()))


def find_ids(term):
    result = set()
    for iv, ciphertext in search_index.get(search_token(term), []):
        cipher = AES.new(index_aes_key, AES.MODE_CBC, bytes.fromhex(iv))
        result.add(unpad(cipher.decrypt(bytes.fromhex(ciphertext)), 16).decode())
    return result


def canonical_bytes(record_id, encrypted_record):
    # Stable bytes for hashing/signing a stored record (grant default).
    # Exclude the hash/signature themselves to avoid a circular definition.
    return json.dumps({"id": record_id, "aes": encrypted_record["aes"],
                       "number_ct": encrypted_record["number_ct"],
                       "wrapped_key": encrypted_record["wrapped_key"]},
                      sort_keys=True, separators=(",", ":")).encode()


def print_encryption(packet):
    if "iv" in packet:
        print("IV(hex):", packet["iv"])
    if "nonce" in packet:
        print("Nonce(hex):", packet["nonce"])
    print(f"AES-{AES_BITS}-{AES_MODE} CT(hex):", packet["ciphertext"])
    if "tag" in packet:
        print("GCM tag(hex):", packet["tag"])


def print_signature(signature):
    if signature["scheme"] == "RSA-PSS":
        print("RSA signature(hex):", signature["value"][:64] + "...")
    elif signature["scheme"] == "ELGAMAL":
        print("ElGamal signature (r, s):", (signature["r"], signature["s"]))
    else:
        print("Schnorr signature (e, s):", (signature["e"], signature["s"]))


# ============================================================================
# STEP 0 CONTINUED: start server clock, all keys, records and lookup index.
# This voting sample keeps records in memory, like the previous voting file.
# ============================================================================
if FIXED_SAMPLE and (AES_BITS, AES_MODE, WRAP_METHOD) != (256, "CBC", "RSA-OAEP"):
    raise SystemExit("FIXED_SAMPLE needs AES-256-CBC and RSA-OAEP")
if AES_BITS not in (128, 192, 256) or RSA_BITS not in (2048, 4096):
    raise SystemExit("Check AES_BITS / RSA_BITS at the top")
if AES_MODE not in ("ECB", "CBC", "CTR", "GCM"):
    raise SystemExit("Check AES_MODE at the top")
if HASH_METHOD not in HASH_FUNCTIONS or SIGN_METHOD not in ("RSA-PSS", "ELGAMAL", "SCHNORR"):
    raise SystemExit("Check HASH_METHOD / SIGN_METHOD at the top")

key_state = make_all_keys()
activate_keys(key_state)
if FIXED_SAMPLE:
    shared_aes_key = SAMPLE_KEY

IST = ZoneInfo("Asia/Kolkata")
now = datetime.now(IST)
VOTING_START = now - timedelta(hours=1)
VOTING_END = now + timedelta(hours=2)
records = {}                       # ballot ID -> encrypted/signed ballot data
search_index = {}                  # search token -> encrypted matching IDs
aggregate = None                  # only combined count ciphertexts

# Educational 2-share reconstruction. This is NOT a true distributed
# threshold Paillier scheme: both shares live inside this one process.
share_modulus = getPrime(600)
lam, _ = paillier_private
share_a = secrets.randbelow(share_modulus)
share_b = (lam - share_a) % share_modulus


# ============================================================================
# STEP 5A: CLIENT ENTERS ID + TWO DETAILS; SENDS AN ENCRYPTED/SIGNED RECORD.
# If your question is about something besides voting, change these THREE
# input labels and the ballot text; Steps 1–4 can stay as they are.
# ============================================================================
def client_submit():
    ballot_id = input("Ballot ID: ").strip().upper()
    if not ballot_id or ballot_id in records:
        print("Invalid or duplicate Ballot ID")
        return
    try:
        candidate = int(input("Candidate ID: "))       # detail 1: counted category
        constituency = int(input("Constituency ID: ")) # detail 2: searchable metadata
        if candidate not in CATEGORIES or constituency <= 0:
            raise ValueError
    except ValueError:
        print("Enter an allowed candidate and a positive constituency ID")
        return

    # 1. Make the readable ballot, then fingerprint it (SHA512 sample).
    ballot = f"CandidateID={candidate};ConstituencyID={constituency}".encode()
    digest = new_hash(ballot)
    signature = sign_digest(digest)                 # private key signs the hash

    # 2. AES locks ballot; RSA/ElGamal/ECC can lock the AES KEY separately.
    aes_key = shared_aes_key if WRAP_METHOD == "SHARED" else (
        SAMPLE_KEY if FIXED_SAMPLE else get_random_bytes(AES_BITS//8))
    fixed_iv = SAMPLE_IVS.get(ballot_id) if FIXED_SAMPLE else None
    aes_packet = aes_encrypt(ballot, aes_key, fixed_iv)
    wrapped_key = wrap_key(aes_key)

    # 3. Paillier separately locks the actual numerical candidate ID.
    # For a proper FREQUENCY, also encrypt 1 for the chosen candidate, 0 others.
    candidate_ct = paillier_encrypt(candidate, SAMPLE_R.get(ballot_id) if FIXED_SAMPLE else None)
    counts_ct = {
        str(item): (candidate_ct if item == candidate == 1 else
                    paillier_encrypt(int(item == candidate)))
        for item in CATEGORIES
    }
    timestamp = datetime.now(IST)                  # local server clock
    record = {
        "aes": aes_packet, "wrapped_key": wrapped_key,
        "hash": digest.hexdigest(), "signature": signature,
        "number_ct": str(candidate_ct), "counts_ct": {k: str(v) for k, v in counts_ct.items()},
        "timestamp": timestamp.isoformat(),
    }

    # Extra signature binds the encrypted vote/counts and timestamp to the
    # ballot. The sample's main signature above still signs the BALLOT hash.
    record["package_signature"] = sign_digest(new_hash(vote_package_bytes(ballot_id, record)))
    records[ballot_id] = record

    # 4. Index constituency and time without indexing the candidate choice.
    add_to_index(f"constituency:{constituency}", ballot_id)
    add_to_index("time:" + timestamp.strftime("%Y-%m-%d %H:%M"), ballot_id)

    print("Ballot UTF-8:", ballot.decode())
    print(f"{HASH_METHOD}(hex):", digest.hexdigest())
    print_encryption(aes_packet)
    if WRAP_METHOD == "RSA-OAEP":
        print(f"RSA-{RSA_BITS} wrapped AES key(hex):",
              wrapped_key["value"][:64] + "...", f"({len(bytes.fromhex(wrapped_key['value']))} bytes)")
    else:
        print("AES key delivery:", WRAP_METHOD)
    print_signature(signature)
    print("Paillier candidate ID CT(hex):", hex(candidate_ct))
    for item in CATEGORIES:
        print(f"Paillier candidate-{item} count CT(hex):", hex(counts_ct[str(item)]))
    print("Timestamp:", timestamp.strftime("%d-%m-%Y %H:%M:%S IST"))
    print(ballot_id, "submitted; constituency/time indexed")


def vote_package_bytes(ballot_id, record):
    # This secondary signed package protects fields outside the ballot text.
    return json.dumps({"id": ballot_id, "aes": record["aes"],
                       "wrapped_key": record["wrapped_key"],
                       "number_ct": record["number_ct"],
                       "counts_ct": record["counts_ct"],
                       "timestamp": record["timestamp"]},
                      sort_keys=True, separators=(",", ":")).encode()


# ============================================================================
# STEP 5B: SERVER CHECKS signature, hash, timestamp (never opens vote CT).
# ============================================================================
def server_verify(ballot_id, verbose=True):
    record = records.get(ballot_id)
    if not isinstance(record, dict):
        if verbose:
            print("Ballot not found")
        return False
    try:
        key = unwrap_key(record["wrapped_key"])
        ballot = aes_decrypt(record["aes"], key)
        digest = new_hash(ballot)
        hash_ok = hmac.compare_digest(digest.hexdigest(), record["hash"])
        signature_ok = signature_valid(digest, record["signature"])
        package_ok = signature_valid(new_hash(vote_package_bytes(ballot_id, record)),
                                     record["package_signature"])
        timestamp = datetime.fromisoformat(record["timestamp"])
        time_ok = VOTING_START <= timestamp <= VOTING_END
        n, _ = paillier_public
        numbers = [int(record["number_ct"])] + [int(record["counts_ct"][str(c)])
                                                     for c in CATEGORIES]
        numbers_ok = all(0 < c < n*n and math.gcd(c, n) == 1 for c in numbers)
    except (ValueError, TypeError, KeyError, OverflowError, UnicodeError):
        hash_ok = signature_ok = package_ok = time_ok = numbers_ok = False

    accepted = hash_ok and signature_ok and package_ok and time_ok and numbers_ok
    if verbose:
        print("AES and key recovery:", "OK" if hash_ok else "FAILED")
        print(f"{HASH_METHOD} hash:", "matches" if hash_ok else "MISMATCH")
        print(SIGN_METHOD, "signature:", "valid" if signature_ok else "INVALID")
        print("Encrypted fields signature:", "valid" if package_ok else "INVALID")
        print("Timestamp:", "within period" if time_ok else "INVALID")
        print(ballot_id, "accepted" if accepted else "rejected")
    return accepted


def server_search():
    option = input("Search 1 Constituency / 2 Time range: ").strip()
    if option == "1":
        value = input("Constituency ID: ").strip()
        ids = find_ids("constituency:" + value)
    elif option == "2":
        try:
            start = datetime.strptime(input("From (HH:MM): "), "%H:%M")
            end = datetime.strptime(input("To (HH:MM): "), "%H:%M")
            if end < start:
                raise ValueError
            day = datetime.now(IST).strftime("%Y-%m-%d")
            ids = set()
            while start <= end:
                ids |= find_ids("time:" + day + " " + start.strftime("%H:%M"))
                start += timedelta(minutes=1)
        except ValueError:
            print("Invalid time range; use HH:MM on today's date")
            return
    else:
        print("Invalid choice")
        return
    print("Matching ballot IDs:", ", ".join(sorted(ids)) or "None")
    print("Ballot contents remain encrypted")


# ============================================================================
# STEP 6A: FREQUENCY TASK. Each ballot supplies encrypted 1/0 per category.
# Paillier multiplication of ciphertexts ADDS these 1/0 values.
# For a SUM-OF-AMOUNTS task, copy finance_task() from sample type 2 instead.
# ============================================================================
def tally_task():
    global aggregate
    aggregate = None
    ids = [s.strip().upper() for s in input("Ballot IDs, comma-separated: ").split(",")]
    n, _ = paillier_public
    if (not ids or any(not x for x in ids) or len(ids) >= n or
            len(set(ids)) != len(ids) or any(not server_verify(x, False) for x in ids)):
        print("Invalid, repeated, or unverified ballot ID")
        return
    combined = {str(candidate): paillier_add(
        [int(records[ballot_id]["counts_ct"][str(candidate)]) for ballot_id in ids]
    ) for candidate in CATEGORIES}
    aggregate = {"ids": ids, "combined": combined}
    for candidate in CATEGORIES:
        print(f"Candidate {candidate} combined CT(hex):", hex(combined[str(candidate)]))
    print("Only combined ciphertexts will be decrypted")


def task_decrypt_total():
    if aggregate is None:
        print("Aggregate ballots first")
        return
    if any(not server_verify(x, False) for x in aggregate["ids"]):
        print("Aggregate rejected: invalid/tampered ballot")
        return
    # Educational two-share approval: reconstruct lambda only here.
    lam = (share_a + share_b) % share_modulus
    n, _ = paillier_public
    mu = pow(lam, -1, n)
    print("Two authority shares combined")
    for candidate in CATEGORIES:
        ct = aggregate["combined"][str(candidate)]
        total = (((pow(ct, lam, n*n) - 1)//n)*mu) % n
        print(f"Candidate {candidate} total:", total)
    print("Individual votes were not decrypted")


# ============================================================================
# STEP 6B: MENUS. Role labels: CLIENT submits; SERVER checks/searches;
# TALLY TASK adds ciphertexts and opens only the combined counts.
# These are role menus only; a real login system would need credentials.
# ============================================================================
def role_menu(role):
    while True:
        if role == "client":
            choice = input("\nCLIENT (VOTER): 1 Submit ballot | 2 Back: ")
            if choice == "1":
                client_submit()
            elif choice == "2":
                return
        elif role == "server":
            choice = input("\nSERVER: 1 Verify | 2 Search index | 3 Back: ")
            if choice == "1":
                server_verify(input("Ballot ID: ").strip().upper())
            elif choice == "2":
                server_search()
            elif choice == "3":
                return
        else:
            choice = input("\nTALLY TASK: 1 Aggregate | 2 Threshold decrypt | 3 Back: ")
            if choice == "1":
                tally_task()
            elif choice == "2":
                task_decrypt_total()
            elif choice == "3":
                return
        if choice not in (("1", "2") if role == "client" else ("1", "2", "3")):
            print("Invalid choice")


if __name__ == "__main__":
    while True:
        choice = input("\nMAIN: 1 Client (Voter) | 2 Server | 3 Tally Task | 4 Exit: ")
        if choice == "1":
            role_menu("client")
        elif choice == "2":
            role_menu("server")
        elif choice == "3":
            role_menu("tally")
        elif choice == "4":
            break
        else:
            print("Invalid choice")
