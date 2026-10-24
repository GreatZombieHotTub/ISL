"""SAMPLE TYPE 2: GRANT / SUM-OF-AMOUNTS TEMPLATE (self-contained after assembly).

Install in Colab: !pip install pycryptodome cryptography
Run: python sample_type_2_amounts.py

EXAM EDIT MAP: change the choices below, then change the two input labels
inside client_submit() if your question uses different details.

Example: ID G001, detail 1 description="Lab equipment", detail 2 amount=500.
The numeric task is a SUM: encrypt 500 and 700; Paillier adds to 1200.

Copying between the two files: Steps 0–4 have the SAME function names.
Only STEP 5 (client/server) and STEP 6 (numeric task/menus) differ.
No sockets: client/server here are roles within a single menu program.
"""

# ===================== EDIT THESE EXAM CHOICES =====================
AES_BITS = 192             # OPTIONS: 128, 192, 256. Key bytes: 16, 24, 32.
AES_MODE = "CBC"           # OPTIONS: "ECB", "CBC", "CTR", "GCM".
HASH_METHOD = "MD5"       # OPTIONS: "MD5", "SHA256", "SHA512".
SIGN_METHOD = "RSA-PSS"   # OPTIONS: "RSA-PSS", "ELGAMAL", "SCHNORR".
WRAP_METHOD = "SHARED"    # OPTIONS: "SHARED", "RSA-OAEP", "ELGAMAL", "ECC-ECDH".
RSA_BITS = 2048            # OPTIONS: 2048, 4096. Signatures and optional wrap.
FIXED_SAMPLE = False      # True gives paper's small Paillier n=3127 (not exact CT).
MAX_AMOUNT = 10**12       # Valid amount: positive integer up to this value.

# Two persistent files. Keep BOTH together across restarts and keep keys private.
KEY_FILE = "type2_keys.json"
RECORD_FILE = "type2_records.json"
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
    # Stable bytes for a SECOND signature protecting stored ciphertext fields.
    # The main grant hash below is of the ORIGINAL plaintext before AES.
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
# STEP 0 CONTINUED: persistent records AND persistent keys.
# Without the original AES, RSA and Paillier keys, old records cannot be read.
# Saved private keys have OS 0600 permissions where supported; this is a
# classroom file-based example, not an authenticated production server.
# ============================================================================
KEY_FILE = Path(KEY_FILE)
RECORD_FILE = Path(RECORD_FILE)
if AES_BITS not in (128, 192, 256) or RSA_BITS not in (2048, 4096):
    raise SystemExit("Check AES_BITS / RSA_BITS at the top")
if AES_MODE not in ("ECB", "CBC", "CTR", "GCM"):
    raise SystemExit("Check AES_MODE at the top")
if HASH_METHOD not in HASH_FUNCTIONS or SIGN_METHOD not in ("RSA-PSS", "ELGAMAL", "SCHNORR"):
    raise SystemExit("Check HASH_METHOD / SIGN_METHOD at the top")


def save_json(path, data):
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
    os.replace(temporary, path)


choice_snapshot = {"aes_bits": AES_BITS, "aes_mode": AES_MODE, "hash": HASH_METHOD,
                   "sign": SIGN_METHOD, "wrap": WRAP_METHOD, "rsa_bits": RSA_BITS,
                   "fixed_sample": FIXED_SAMPLE, "hash_basis": "original_plaintext"}
if KEY_FILE.exists() != RECORD_FILE.exists():
    raise SystemExit("A saved file is missing. Restore BOTH the keys and records.")

if KEY_FILE.exists():
    try:
        with KEY_FILE.open(encoding="utf-8") as stream:
            key_state = json.load(stream)
        with RECORD_FILE.open(encoding="utf-8") as stream:
            records = json.load(stream)
        if not isinstance(records, dict):
            raise ValueError("Expected a dictionary of records")
        if key_state["choices"] != choice_snapshot:
            raise ValueError("Choices changed: use a fresh pair of storage files")
        activate_keys(key_state)
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f"Cannot safely load saved grants: {error}") from error
else:
    key_state = make_all_keys()
    key_state["choices"] = choice_snapshot
    activate_keys(key_state)
    records = {}
    save_json(KEY_FILE, key_state)
    save_json(RECORD_FILE, records)

search_index = {}
aggregate = None
for old_id in records:
    add_to_index(old_id, old_id)  # Rebuild index from saved IDs after restart.


# ============================================================================
# STEP 5A: CLIENT ENTERS ID + TWO DETAILS; STORES ENCRYPTED/SIGNED RECORD.
# To adapt another exam question: rename Grant ID, Description, Amount inputs.
# For frequencies instead of amounts, copy client_submit and tally_task from
# sample type 1: store encrypted 1/0 indicators for each category.
# ============================================================================
def original_record_bytes(grant_id, description, amount):
    # Exact, predictable bytes for the ORIGINAL three-field record.
    return json.dumps({"id": grant_id, "description": description, "amount": amount},
                      sort_keys=True, separators=(",", ":")).encode()


def client_submit():
    grant_id = input("Grant ID: ").strip().upper()
    if not grant_id or grant_id in records:
        print("Invalid or duplicate Grant ID")
        return
    description = input("Description: ").strip()     # detail 1: AES text
    try:
        amount = int(input("Amount (whole number): ").strip())  # detail 2: Paillier number
        n, _ = paillier_public
        if not description or not 0 < amount <= MAX_AMOUNT or amount >= n:
            raise ValueError
    except ValueError:
        print("Enter a nonempty description and a positive whole-number amount < Paillier n")
        return

    # 1. Hash and sign the ORIGINAL readable ID + description + amount FIRST.
    original = original_record_bytes(grant_id, description, amount)
    digest = new_hash(original)
    signature = sign_digest(digest)

    # 2. AES locks that entire readable record, including the description.
    # Reviewer must open this AES copy to recompute the plaintext hash.
    # This also gives the reviewer access to the amount internally.
    # Paillier separately locks the amount for finance's encrypted SUM.
    aes_key = shared_aes_key if WRAP_METHOD == "SHARED" else get_random_bytes(AES_BITS//8)
    aes_packet = aes_encrypt(original, aes_key)
    wrapped_key = wrap_key(aes_key)
    amount_ct = paillier_encrypt(amount)
    record = {"aes": aes_packet, "wrapped_key": wrapped_key,
              "number_ct": str(amount_ct)}

    record["hash"] = digest.hexdigest()
    record["signature"] = signature
    # Extra signature binds the AES ciphertext AND Paillier amount ciphertext.
    # Otherwise changing the encrypted amount would not change the plaintext hash.
    record["package_signature"] = sign_digest(new_hash(canonical_bytes(grant_id, record)))
    records[grant_id] = record
    try:
        save_json(RECORD_FILE, records)
    except OSError as error:
        del records[grant_id]
        print("Could not save grant:", error)
        return
    add_to_index(grant_id, grant_id)

    print("Grant ID:", grant_id)
    print_encryption(aes_packet)
    print("Paillier amount CT(hex):", hex(amount_ct))
    print(f"{HASH_METHOD}(hex):", record["hash"])
    print_signature(record["signature"])
    print(grant_id, "submitted and stored")


def client_view_all():
    if not records:
        print("No submitted records")
        return
    # All earlier records, including those from previous runs, remain encrypted.
    for grant_id, record in sorted(records.items()):
        if not isinstance(record, dict):
            print(grant_id, "| Damaged record")
            continue
        aes_packet = record.get("aes", {})
        print(grant_id, "| CT:", aes_packet.get("ciphertext", "?"),
              "| Paillier CT:", record.get("number_ct", "?"),
              "|", HASH_METHOD+":", record.get("hash", "?"))


# ============================================================================
# STEP 5B: SERVER VERIFIES, SEARCHES, AND PRINTS DECRYPTED DESCRIPTION HEX.
# server_verify opens the AES copy to recompute the ORIGINAL plaintext hash.
# It never calls paillier_decrypt() on any individual amount.
# ============================================================================
def server_verify(grant_id, verbose=True):
    record = records.get(grant_id)
    if not isinstance(record, dict):
        if verbose:
            print("Grant not found or damaged")
        return False
    try:
        original = aes_decrypt(record["aes"], unwrap_key(record["wrapped_key"]))
        readable = json.loads(original.decode())
        if (readable["id"] != grant_id or not isinstance(readable["description"], str)
                or not isinstance(readable["amount"], int)
                or not 0 < readable["amount"] <= MAX_AMOUNT):
            raise ValueError("Invalid readable record")
        digest = new_hash(original)      # Rehash the same PRE-ENCRYPTION bytes.
        hash_ok = hmac.compare_digest(digest.hexdigest(), record["hash"])
        signature_ok = signature_valid(digest, record["signature"])
        package_ok = signature_valid(new_hash(canonical_bytes(grant_id, record)),
                                     record["package_signature"])
        n, _ = paillier_public
        ciphertext = int(record["number_ct"])
        number_ok = 0 < ciphertext < n*n and math.gcd(ciphertext, n) == 1
        aes_packet = record["aes"]
        aes_ok = (aes_packet["mode"] == AES_MODE and
                  isinstance(aes_packet["ciphertext"], str) and
                  len(bytes.fromhex(aes_packet["ciphertext"])) > 0)
    except (ValueError, TypeError, KeyError, OverflowError, UnicodeError):
        hash_ok = signature_ok = package_ok = number_ok = aes_ok = False
    verified = hash_ok and signature_ok and package_ok and number_ok and aes_ok
    if verbose:
        print(SIGN_METHOD, "signature:", "valid" if signature_ok else "INVALID")
        print(HASH_METHOD, "hash:", "matches" if hash_ok else "MISMATCH")
        print("Encrypted record signature:", "valid" if package_ok else "INVALID")
        print(grant_id, "verified" if verified else "rejected (invalid/tampered)")
    return verified


def server_search():
    grant_id = input("Grant ID: ").strip().upper()
    ids = find_ids(grant_id)          # No AES text or Paillier amount decrypted.
    if grant_id in ids and grant_id in records:
        print("Record found:", grant_id, "(contents remain encrypted)")
    else:
        print("Record not found")


def server_view_hex():
    grant_id = input("Grant ID: ").strip().upper()
    if not server_verify(grant_id, verbose=False):
        print("Record not found or failed verification")
        return
    try:
        record = records[grant_id]
        original = aes_decrypt(record["aes"], unwrap_key(record["wrapped_key"]))
        description = json.loads(original.decode())["description"]
        print(f"AES-{AES_BITS} decrypted text:", description)
        print("Decrypted hex:", description.encode().hex()) # Hex of description only.
    except (ValueError, TypeError, KeyError, UnicodeDecodeError) as error:
        print("Cannot open the description:", error)


# ============================================================================
# STEP 6A: SUM TASK. Multiply encrypted AMOUNTS to add the actual amounts.
# For FREQUENCY, use the first file's encrypted 1/0 per category instead.
# RSA/ElGamal PRODUCT alternatives are in STEP 3 above (not used here).
# ============================================================================
def finance_task():
    global aggregate
    aggregate = None
    ids = [s.strip().upper() for s in input("Grant IDs, comma-separated: ").split(",")]
    if not ids or any(not x for x in ids) or len(set(ids)) != len(ids):
        print("Enter distinct existing Grant IDs")
        return
    # Verify first; a missing/tampered signed record cancels aggregation.
    if any(not server_verify(x, False) for x in ids):
        print("Aggregation cancelled: missing or invalid/tampered grant")
        return
    combined = paillier_add([int(records[x]["number_ct"]) for x in ids])
    aggregate = {"ids": ids, "combined": combined}
    print("Product of Paillier ciphertexts mod n^2(hex):", hex(combined))
    print("Selected signatures and hashes verified")
    print("Only the combined ciphertext will be decrypted")


def task_decrypt_total():
    if aggregate is None:
        print("Aggregate grants first")
        return
    if any(not server_verify(x, False) for x in aggregate["ids"]):
        print("Aggregate rejected: a selected grant failed verification")
        return
    # Paillier gives the sum modulo n; the sample 500+700 < n=3127.
    print("Signatures valid; aggregate decrypted =", paillier_decrypt(aggregate["combined"]))
    print("Finance did not decrypt individual Paillier amounts")


# ============================================================================
# STEP 6B: MENUS. CLIENT submits; SERVER checks/searches;
# FINANCE TASK adds ciphertexts and opens only the combined total.
# These are role menus only; a real login system would need credentials.
# ============================================================================
def role_menu(role):
    while True:
        if role == "client":
            choice = input("\nCLIENT (RESEARCHER): 1 Submit | 2 View all | 3 Back: ")
            if choice == "1":
                client_submit()
            elif choice == "2":
                client_view_all()
            elif choice == "3":
                return
        elif role == "server":
            choice = input("\nSERVER (REVIEWER): 1 Verify | 2 Search index | 3 View decrypted hex | 4 Back: ")
            if choice == "1":
                server_verify(input("Grant ID: ").strip().upper())
            elif choice == "2":
                server_search()
            elif choice == "3":
                server_view_hex()
            elif choice == "4":
                return
        else:
            choice = input("\nFINANCE TASK: 1 Aggregate | 2 Verify and decrypt total | 3 Back: ")
            if choice == "1":
                finance_task()
            elif choice == "2":
                task_decrypt_total()
            elif choice == "3":
                return
        valid = ("1", "2", "3", "4") if role == "server" else ("1", "2", "3")
        if choice not in valid:
            print("Invalid choice")


if __name__ == "__main__":
    while True:
        choice = input("\nMAIN: 1 Client (Researcher) | 2 Server (Reviewer) | 3 Finance Task | 4 Exit: ")
        if choice == "1":
            role_menu("client")
        elif choice == "2":
            role_menu("server")
        elif choice == "3":
            role_menu("finance")
        elif choice == "4":
            break
        else:
            print("Invalid choice")
