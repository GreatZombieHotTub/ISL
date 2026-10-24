"""Travel reimbursement portal: fixed-method, menu-driven Type 2 program.

Install in Colab: !pip install pycryptodome

METHODS USED
1. SHA-256: hash the ORIGINAL readable claim (ID + purpose + amount) first.
2. RSA-2048 PSS: employee signs that hash; reviewer uses RSA public key.
3. AES-128-GCM: encrypt the readable claim using a NEW 16-byte AES key.
   AES blocks are 16 bytes; GCM has a nonce and tag, and needs NO padding.
4. RSA-2048 OAEP: encrypt only that AES key using the reviewer's public key.
5. Paillier: encrypt each amount; finance ADDS encrypted amounts.
6. Lab 8 index: HMAC-SHA256 tokens + AES-CBC-encrypted claim IDs.
7. JSON files: keep encrypted records and keys across program restarts.

The reviewer opens the AES copy to rehash the full original claim, so the
reviewer can read an individual amount. Finance decrypts only the combined
Paillier ciphertext.

Sample: C001 / Lab sensors / 450 and C002 / Field travel / 750 -> total 1200.
No sockets: client, server and finance are menus in one program.
"""

import hashlib
import hmac
import json
import math
import os
import secrets
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime


# STEP 0: Create keys on first run; reload SAME keys on later runs.
KEY_FILE = Path("claim_keys.json")
RECORD_FILE = Path("claim_records.json")
MAX_AMOUNT = 10**9


def save_json(path, data):
    temp = path.with_name(path.name + ".tmp")
    descriptor = os.open(
        temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
    )

    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)

    os.replace(temp, path)


def make_paillier_keys():
    while True:
        p, q = getPrime(256), getPrime(256)
        n = p * q
        lam = math.lcm(p - 1, q - 1)

        if p != q and math.gcd(lam, n) == 1:
            return (n, n + 1), (lam, pow(lam, -1, n))


if KEY_FILE.exists() != RECORD_FILE.exists():
    raise SystemExit(
        "One saved file is missing. Restore BOTH keys and records."
    )

if KEY_FILE.exists():
    try:
        with KEY_FILE.open(encoding="utf-8") as stream:
            saved_keys = json.load(stream)

        with RECORD_FILE.open(encoding="utf-8") as stream:
            records = json.load(stream)

        if not isinstance(records, dict):
            raise ValueError("Invalid records file")

        rsa_private = RSA.import_key(saved_keys["rsa_private"])
        paillier_public = tuple(saved_keys["paillier_public"])
        paillier_private = tuple(saved_keys["paillier_private"])
        index_key = bytes.fromhex(saved_keys["index_key"])
        index_aes_key = bytes.fromhex(saved_keys["index_aes_key"])

    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(
            f"Cannot load saved claims safely: {error}"
        ) from error

else:
    print("Generating RSA-2048 and Paillier keys; please wait...")

    rsa_private = RSA.generate(2048)
    paillier_public, paillier_private = make_paillier_keys()
    index_key = get_random_bytes(32)
    index_aes_key = get_random_bytes(16)
    records = {}

    save_json(KEY_FILE, {
        "rsa_private": rsa_private.export_key().decode(),
        "paillier_public": paillier_public,
        "paillier_private": paillier_private,
        "index_key": index_key.hex(),
        "index_aes_key": index_aes_key.hex(),
    })

    save_json(RECORD_FILE, records)


rsa_public = rsa_private.publickey()
search_index = {}
aggregate = None


# STEP 1: Hash and RSA-sign the ORIGINAL plaintext record.
def original_record_bytes(claim_id, purpose, amount):
    fields = {
        "id": claim_id,
        "purpose": purpose,
        "amount": amount
    }

    return json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":")
    ).encode()


def sign_digest(digest):
    return pss.new(rsa_private).sign(digest)


def signature_valid(digest, signature):
    try:
        pss.new(rsa_public).verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False


# STEP 2: AES-128-GCM encrypts the record; RSA wraps its AES key.
def aes_encrypt(data, key):
    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=get_random_bytes(12)
    )

    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag


def aes_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# STEP 3: Paillier encrypts amounts and adds them while encrypted.
def paillier_encrypt(number):
    n, g = paillier_public

    while True:
        r = secrets.randbelow(n - 1) + 1
        if math.gcd(r, n) == 1:
            break

    return (
        pow(g, number, n * n) *
        pow(r, n, n * n)
    ) % (n * n)


def paillier_add(ciphertexts):
    n, _ = paillier_public
    combined = 1

    for ciphertext in ciphertexts:
        combined = combined * ciphertext % (n * n)

    return combined


def paillier_decrypt(combined):
    # Use only on the combined ciphertext.
    n, _ = paillier_public
    lam, mu = paillier_private

    value = (pow(combined, lam, n * n) - 1) // n
    return value * mu % n


# STEP 4: Search through the index without opening claim contents.
def search_token(term):
    return hmac.new(
        index_key,
        term.upper().encode(),
        hashlib.sha256
    ).hexdigest()


def add_to_index(term, claim_id):
    cipher = AES.new(index_aes_key, AES.MODE_CBC)
    encrypted_id = cipher.encrypt(pad(claim_id.encode(), 16))

    search_index.setdefault(
        search_token(term), []
    ).append((cipher.iv, encrypted_id))


def find_ids(term):
    found = set()

    for iv, ciphertext in search_index.get(search_token(term), []):
        cipher = AES.new(index_aes_key, AES.MODE_CBC, iv)
        claim_id = unpad(cipher.decrypt(ciphertext), 16).decode()
        found.add(claim_id)

    return found


# Rebuild the search index from saved IDs after a restart.
for saved_id in records:
    add_to_index(saved_id, saved_id)


def encrypted_record_bytes(claim_id, record):
    # The second signature protects all stored ciphertext fields.
    fields = {
        "id": claim_id,
        "nonce": record["nonce"],
        "ciphertext": record["ciphertext"],
        "tag": record["tag"],
        "wrapped_key": record["wrapped_key"],
        "amount_ct": record["amount_ct"]
    }

    return json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":")
    ).encode()


# STEP 5A: CLIENT submits Claim ID + purpose + amount.
def client_submit():
    claim_id = input("Claim ID: ").strip().upper()

    if not claim_id or claim_id in records:
        print("Invalid or duplicate Claim ID")
        return

    purpose = input("Purpose: ").strip()

    try:
        amount = int(input("Amount (whole number): ").strip())
        n, _ = paillier_public

        if not purpose or not 0 < amount <= MAX_AMOUNT or amount >= n:
            raise ValueError

    except ValueError:
        print("Enter a purpose and a positive whole-number amount")
        return

    # FIRST: hash and sign the original readable claim.
    original = original_record_bytes(claim_id, purpose, amount)
    digest = SHA256.new(original)
    signature = sign_digest(digest)

    # SECOND: encrypt the claim and protect its AES key.
    aes_key = get_random_bytes(16)
    nonce, ciphertext, tag = aes_encrypt(original, aes_key)
    wrapped_key = PKCS1_OAEP.new(rsa_public).encrypt(aes_key)

    # THIRD: encrypt the amount separately for finance.
    amount_ct = paillier_encrypt(amount)

    record = {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
        "wrapped_key": wrapped_key.hex(),
        "amount_ct": str(amount_ct),
        "hash": digest.hexdigest(),
        "signature": signature.hex()
    }

    package_digest = SHA256.new(
        encrypted_record_bytes(claim_id, record)
    )

    record["package_signature"] = sign_digest(
        package_digest
    ).hex()

    records[claim_id] = record

    try:
        save_json(RECORD_FILE, records)
    except OSError as error:
        del records[claim_id]
        print("Could not save claim:", error)
        return

    add_to_index(claim_id, claim_id)

    print("Claim ID:", claim_id)
    print("SHA-256 of original claim(hex):", record["hash"])
    print("AES-128-GCM nonce(hex):", record["nonce"])
    print("AES-128-GCM CT(hex):", record["ciphertext"])
    print("GCM tag(hex):", record["tag"])
    print(
        "RSA-2048 wrapped AES key(hex):",
        record["wrapped_key"][:64] + "..."
    )
    print(
        "RSA-PSS signature(hex):",
        record["signature"][:64] + "..."
    )
    print("Paillier amount CT(hex):", hex(amount_ct))
    print(claim_id, "submitted and saved")


def client_view_all():
    if not records:
        print("No submitted claims")
        return

    for claim_id, record in sorted(records.items()):
        if not isinstance(record, dict):
            print(claim_id, "| Damaged record")
            continue

        print(
            claim_id,
            "| AES CT:", record.get("ciphertext", "?"),
            "| Paillier CT:", record.get("amount_ct", "?"),
            "| SHA-256:", record.get("hash", "?")
        )


# STEP 5B: SERVER checks the hash, signatures and GCM tag.
def server_verify(claim_id, verbose=True):
    record = records.get(claim_id)

    if not isinstance(record, dict):
        if verbose:
            print("Claim not found or damaged")
        return False

    try:
        aes_key = PKCS1_OAEP.new(rsa_private).decrypt(
            bytes.fromhex(record["wrapped_key"])
        )

        original = aes_decrypt(
            bytes.fromhex(record["nonce"]),
            bytes.fromhex(record["ciphertext"]),
            bytes.fromhex(record["tag"]),
            aes_key
        )

        readable = json.loads(original.decode())

        if (
            readable["id"] != claim_id or
            not isinstance(readable["purpose"], str) or
            not isinstance(readable["amount"], int) or
            not 0 < readable["amount"] <= MAX_AMOUNT
        ):
            raise ValueError("Invalid original record")

        # Recompute SHA-256 from the recovered original claim.
        digest = SHA256.new(original)

        hash_ok = hmac.compare_digest(
            digest.hexdigest(),
            record["hash"]
        )

        signature_ok = signature_valid(
            digest,
            bytes.fromhex(record["signature"])
        )

        package_digest = SHA256.new(
            encrypted_record_bytes(claim_id, record)
        )

        package_ok = signature_valid(
            package_digest,
            bytes.fromhex(record["package_signature"])
        )

        n, _ = paillier_public
        amount_ct = int(record["amount_ct"])

        amount_ct_ok = (
            0 < amount_ct < n * n and
            math.gcd(amount_ct, n) == 1
        )

    except (ValueError, TypeError, KeyError, OverflowError, UnicodeError):
        hash_ok = False
        signature_ok = False
        package_ok = False
        amount_ct_ok = False

    verified = (
        hash_ok and signature_ok and
        package_ok and amount_ct_ok
    )

    if verbose:
        print(
            "SHA-256 of original claim:",
            "matches" if hash_ok else "MISMATCH"
        )
        print(
            "RSA-PSS signature:",
            "valid" if signature_ok else "INVALID"
        )
        print(
            "Stored ciphertext signature:",
            "valid" if package_ok else "INVALID"
        )
        print(
            claim_id,
            "verified" if verified else "rejected (invalid/tampered)"
        )

    return verified


def server_search():
    claim_id = input("Claim ID: ").strip().upper()

    if claim_id in find_ids(claim_id) and claim_id in records:
        print(
            "Record found:",
            claim_id,
            "(contents remain encrypted)"
        )
    else:
        print("Record not found")


def server_view_hex():
    claim_id = input("Claim ID: ").strip().upper()

    if not server_verify(claim_id, verbose=False):
        print("Claim not found or failed verification")
        return

    try:
        record = records[claim_id]

        aes_key = PKCS1_OAEP.new(rsa_private).decrypt(
            bytes.fromhex(record["wrapped_key"])
        )

        original = aes_decrypt(
            bytes.fromhex(record["nonce"]),
            bytes.fromhex(record["ciphertext"]),
            bytes.fromhex(record["tag"]),
            aes_key
        )

        purpose = json.loads(original.decode())["purpose"]

        print("AES-128-GCM decrypted purpose:", purpose)
        print("Decrypted purpose hex:", purpose.encode().hex())

    except (ValueError, TypeError, KeyError, UnicodeError):
        print("Cannot open the purpose")


# STEP 6A: FINANCE adds ciphertexts, then decrypts only the total.
def finance_task():
    global aggregate
    aggregate = None

    ids = [
        x.strip().upper()
        for x in input("Claim IDs, comma-separated: ").split(",")
    ]

    if (
        not ids or
        any(not x for x in ids) or
        len(set(ids)) != len(ids)
    ):
        print("Enter distinct existing Claim IDs")
        return

    if any(not server_verify(x, verbose=False) for x in ids):
        print("Aggregation cancelled: missing or invalid/tampered claim")
        return

    combined = paillier_add([
        int(records[x]["amount_ct"])
        for x in ids
    ])

    aggregate = {"ids": ids, "combined": combined}

    print(
        "Product of Paillier ciphertexts mod n^2(hex):",
        hex(combined)
    )
    print("Only the combined ciphertext will be decrypted")


def task_decrypt_total():
    if aggregate is None:
        print("Aggregate claims first")
        return

    if any(
        not server_verify(x, verbose=False)
        for x in aggregate["ids"]
    ):
        print("Aggregate rejected: a selected claim failed verification")
        return

    total = paillier_decrypt(aggregate["combined"])

    print("Signatures valid; aggregate decrypted =", total)
    print("Finance did not decrypt individual Paillier amounts")


# STEP 6B: Menus are required by the lab question.
def role_menu(role):
    while True:
        if role == "client":
            choice = input(
                "\nCLIENT: 1 Submit claim | 2 View all | 3 Back: "
            )

            if choice == "1":
                client_submit()
            elif choice == "2":
                client_view_all()
            elif choice == "3":
                return

        elif role == "server":
            choice = input(
                "\nSERVER: 1 Verify | 2 Search index | "
                "3 View decrypted hex | 4 Back: "
            )

            if choice == "1":
                claim_id = input("Claim ID: ").strip().upper()
                server_verify(claim_id)
            elif choice == "2":
                server_search()
            elif choice == "3":
                server_view_hex()
            elif choice == "4":
                return

        else:
            choice = input(
                "\nFINANCE: 1 Aggregate | 2 Decrypt total | 3 Back: "
            )

            if choice == "1":
                finance_task()
            elif choice == "2":
                task_decrypt_total()
            elif choice == "3":
                return

        valid = (
            ("1", "2", "3", "4")
            if role == "server"
            else ("1", "2", "3")
        )

        if choice not in valid:
            print("Invalid choice")


if __name__ == "__main__":
    while True:
        choice = input(
            "\nMAIN: 1 Client | 2 Server | 3 Finance | 4 Exit: "
        )

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

"""
try C001 / Lab sensors / 450 and 
C002 / Field travel / 750. 
The total should be 1200.
"""