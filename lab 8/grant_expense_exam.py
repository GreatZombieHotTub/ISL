"""Menu-driven grant expense lab program. Run with pycryptodome installed.

Story: the researcher locks and signs each grant; the reviewer checks and
searches it; finance adds encrypted amounts and opens only the final total.

Run in the same folder each time: the keys and grants are saved there.
"""

"""ORIGINAL SAMPLE QUESTION 2: GRANT EXPENSE RECORDS

OBJECTIVES (what the question wants):
1. Researcher enters a grant ID, description, and amount.
2. Hash the ORIGINAL full record with MD5 before encrypting it, then sign
   that hash with the researcher's RSA-2048 private key (PSS).
3. Encrypt the record with AES-192 in CBC mode. Encrypt the amount
   separately with Paillier so finance can add amounts while encrypted.
4. Reviewer finds a record by grant ID using an encrypted search index,
   verifies the signatures, decrypts the record, and checks its MD5 hash.
5. Show the description in ordinary text and UTF-8 hexadecimal.
6. Finance combines Paillier ciphertexts and decrypts the combined TOTAL.
7. Offer separate Researcher, Reviewer, and Finance menus and save the
   keys and records so a later run can open the same records.

METHODS USED: MD5 of plaintext | RSA-2048-PSS signatures | AES-192-CBC |
Paillier addition | encrypted grant-ID search index | saved JSON files.

PRACTICE INPUT: G001 Lab equipment 500 + G002 Field travel 700 = 1200.
"Lab equipment" in UTF-8 hex is 4C61622065717569706D656E74.

The reviewer can read the amount inside the decrypted AES record; finance
only opens the combined Paillier total. This is one local program, without
sockets. Keep grant_keys.json and grant_records.json together between runs.
Run with pycryptodome installed.
"""

import hashlib
import hmac
import json
import math
import os
import secrets
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime


# Run once in Colab: !pip install pycryptodome
# Keep these two files together between runs. The keys file is private.
KEY_FILE = Path("grant_keys.json")
RECORD_FILE = Path("grant_records.json")
MAX_AMOUNT = 10**12


def save_json(path, data):
    # Write a complete new file before replacing the old one.
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
    os.replace(temporary, path)


def make_paillier_keys():
    # Same idea as Lab 7: public (n, g), private (lambda, mu).
    while True:
        p, q = getPrime(256), getPrime(256)
        n = p * q
        lam = math.lcm(p - 1, q - 1)
        if p != q and math.gcd(lam, n) == 1:
            return (n, n + 1), (lam, pow(lam, -1, n))


# STEP 0: Make keys on the first run; LOAD THE SAME keys on later runs.
# If keys changed, older encrypted records could no longer be read.
if KEY_FILE.exists() != RECORD_FILE.exists():
    raise SystemExit("One storage file is missing; restore both files together.")

if KEY_FILE.exists():
    try:
        with KEY_FILE.open(encoding="utf-8") as stream:
            saved_keys = json.load(stream)
        with RECORD_FILE.open(encoding="utf-8") as stream:
            records = json.load(stream)
        rsa_private = RSA.import_key(saved_keys["rsa_private"])
        aes_key = bytes.fromhex(saved_keys["aes_key"])
        index_key = bytes.fromhex(saved_keys["index_key"])
        index_aes_key = bytes.fromhex(saved_keys["index_aes_key"])
        paillier_public = tuple(saved_keys["paillier_public"])
        paillier_private = tuple(saved_keys["paillier_private"])
        if not isinstance(records, dict) or len(aes_key) != 24:
            raise ValueError("Invalid stored data")
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit(f"Cannot load saved grants safely: {error}") from error
else:
    print("Generating keys; please wait...")
    rsa_private = RSA.generate(2048)
    aes_key = get_random_bytes(24)         # 24 bytes = AES-192
    index_key = get_random_bytes(32)
    index_aes_key = get_random_bytes(16)
    paillier_public, paillier_private = make_paillier_keys()
    records = {}
    save_json(KEY_FILE, {
        "rsa_private": rsa_private.export_key().decode(),
        "aes_key": aes_key.hex(),
        "index_key": index_key.hex(),
        "index_aes_key": index_aes_key.hex(),
        "paillier_public": paillier_public,
        "paillier_private": paillier_private,
    })
    save_json(RECORD_FILE, records)

rsa_public = rsa_private.publickey()      # Reviewer uses this to verify.
search_index = {}                        # Protected lookup; rebuilt at startup.
aggregate = None                         # Selected IDs + their combined CT.


# STEP 1: Hash the ORIGINAL readable record BEFORE AES, then RSA-sign it.
def original_record_bytes(grant_id, description, amount):
    return json.dumps({"id": grant_id, "description": description, "amount": amount},
                      sort_keys=True, separators=(",", ":")).encode()


# Separately sign the STORED ciphertext fields so Paillier CT is protected too.
def record_bytes(grant_id, record):
    fields = {
        "grant_id": grant_id,
        "iv": record["iv"],
        "description_ct": record["ciphertext"],
        "amount_ct": record["amount_ct"],
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def sign_digest(digest):
    # Researcher's RSA PRIVATE key signs the MD5 object.
    return pss.new(rsa_private).sign(digest)


def signature_valid(digest, signature):
    # Reviewer uses the corresponding RSA PUBLIC key.
    try:
        pss.new(rsa_public).verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False


# STEP 2: AES-192-CBC locks the description (Lab 2).
# A new random IV makes repeated descriptions produce different ciphertexts.
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv, cipher.encrypt(pad(data, AES.block_size))


def aes_decrypt(iv, ciphertext, key):
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)


# STEP 3: Paillier locks an amount; encrypted amounts can still be ADDED (Lab 7).
def paillier_encrypt(number):
    n, g = paillier_public
    while True:
        random_r = secrets.randbelow(n - 1) + 1
        if math.gcd(random_r, n) == 1:
            break
    return (pow(g, number, n*n) * pow(random_r, n, n*n)) % (n*n)


def paillier_decrypt(ciphertext):
    # Finance calls this ONLY on the combined ciphertext.
    n, _ = paillier_public
    lam, mu = paillier_private
    value = (pow(ciphertext, lam, n*n) - 1) // n
    return (value * mu) % n


# STEP 4: Find a Grant ID through an index, without opening its contents (Lab 8).
def search_token(term):
    return hmac.new(index_key, term.upper().encode(), hashlib.sha256).hexdigest()


def add_to_index(term, grant_id):
    iv, ciphertext = aes_encrypt(grant_id.encode(), index_aes_key)
    search_index.setdefault(search_token(term), []).append((iv, ciphertext))


def find_ids(term):
    return {
        aes_decrypt(iv, ciphertext, index_aes_key).decode()
        for iv, ciphertext in search_index.get(search_token(term), [])
    }


# The index itself need not be saved: rebuild it from saved Grant IDs.
for saved_id in records:
    add_to_index(saved_id, saved_id)


def submit_grant():
    grant_id = input("Grant ID: ").strip().upper()
    if not grant_id or grant_id in records:
        print("Invalid or duplicate Grant ID")
        return
    description = input("Description: ").strip()
    try:
        amount = int(input("Amount (whole number): ").strip())
        if not description or not 0 < amount <= MAX_AMOUNT:
            raise ValueError
    except ValueError:
        print("Enter a nonempty description and a positive whole-number amount")
        return

    # Researcher: hash + sign all THREE readable fields before encryption.
    original = original_record_bytes(grant_id, description, amount)
    digest = MD5.new(original)
    signature = sign_digest(digest)

    # AES locks the full original record. Reviewer will need to open this
    # AES copy to recompute MD5; Paillier separately locks the amount for SUM.
    iv, ciphertext = aes_encrypt(original, aes_key)
    amount_ct = paillier_encrypt(amount)
    record = {
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "amount_ct": str(amount_ct),
        "hash_basis": "original_plaintext",
    }
    record["hash"] = digest.hexdigest()
    record["signature"] = signature.hex()
    record["package_signature"] = sign_digest(MD5.new(record_bytes(grant_id, record))).hex()
    records[grant_id] = record
    try:
        save_json(RECORD_FILE, records)
    except OSError as error:
        del records[grant_id]
        print("Could not save grant:", error)
        return
    add_to_index(grant_id, grant_id)

    print("Grant ID:", grant_id)
    print("AES-192 IV(hex):", record["iv"])
    print("AES-192 CT(hex):", record["ciphertext"])
    print("Paillier amount CT(hex):", hex(amount_ct))
    print("MD5(hex):", record["hash"])
    print("RSA signature(hex):", record["signature"][:64] + "...")
    print(grant_id, "submitted and stored")


def view_submitted():
    if not records:
        print("No submitted grants")
        return
    # Researcher sees earlier saved records, still in encrypted form.
    for grant_id, record in sorted(records.items()):
        if not isinstance(record, dict):
            print(grant_id, "| Damaged record")
            continue
        print(grant_id, "| CT:", record.get("ciphertext", "?"),
              "| Paillier CT:", record.get("amount_ct", "?"),
              "| MD5:", record.get("hash", "?"))


def verify_grant(grant_id, verbose=True):
    record = records.get(grant_id)
    if not isinstance(record, dict):
        if verbose:
            print("Record not found or damaged")
        return False
    try:
        # New records: decrypt the AES copy and rehash ORIGINAL readable bytes.
        # Older saved records used a ciphertext hash; keep them readable too.
        if record.get("hash_basis") == "original_plaintext":
            original = aes_decrypt(bytes.fromhex(record["iv"]),
                                   bytes.fromhex(record["ciphertext"]), aes_key)
            readable = json.loads(original.decode())
            if (readable["id"] != grant_id or not isinstance(readable["description"], str)
                    or not isinstance(readable["amount"], int)
                    or not 0 < readable["amount"] <= MAX_AMOUNT):
                raise ValueError("Invalid readable record")
            digest = MD5.new(original)
            package_ok = signature_valid(MD5.new(record_bytes(grant_id, record)),
                                         bytes.fromhex(record["package_signature"]))
        else:
            digest = MD5.new(record_bytes(grant_id, record))
            package_ok = True
        hash_ok = hmac.compare_digest(digest.hexdigest(), record["hash"])
        sign_ok = signature_valid(digest, bytes.fromhex(record["signature"]))
        n, _ = paillier_public
        amount_ct = int(record["amount_ct"])
        iv, ciphertext = bytes.fromhex(record["iv"]), bytes.fromhex(record["ciphertext"])
        fields_ok = (len(iv) == 16 and len(ciphertext) > 0
                     and len(ciphertext) % 16 == 0
                     and 0 < amount_ct < n*n and math.gcd(amount_ct, n) == 1)
    except (ValueError, TypeError, KeyError, OverflowError, UnicodeError):
        hash_ok = sign_ok = package_ok = fields_ok = False

    good = hash_ok and sign_ok and package_ok and fields_ok
    if verbose:
        print("RSA signature:", "valid" if sign_ok else "INVALID")
        print("MD5:", "matches" if hash_ok else "MISMATCH")
        print("Stored ciphertext signature:", "valid" if package_ok else "INVALID")
        print(grant_id, "verified" if good else "rejected (invalid/tampered record)")
    return good


def search_grants():
    grant_id = input("Grant ID: ").strip().upper()
    matches = find_ids(grant_id)      # No AES description or Paillier decryption.
    if grant_id in matches and grant_id in records:
        print("Record found:", grant_id, "(contents remain encrypted)")
    else:
        print("Record not found")


def view_decrypted_hex():
    grant_id = input("Grant ID: ").strip().upper()
    if not verify_grant(grant_id, verbose=False):
        print("Record not found or failed verification")
        return
    try:
        record = records[grant_id]
        data = aes_decrypt(bytes.fromhex(record["iv"]),
                           bytes.fromhex(record["ciphertext"]), aes_key)
        description = (json.loads(data.decode())["description"]
                       if record.get("hash_basis") == "original_plaintext"
                       else data.decode())
        print("AES-192 decrypted text:", description)
        print("Decrypted hex:", description.encode().hex())  # Description only.
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        print("Cannot decrypt the stored description")


def aggregate_amounts():
    global aggregate
    aggregate = None
    ids = [item.strip().upper() for item in
           input("Grant IDs, comma-separated: ").split(",")]
    if not ids or any(not item for item in ids) or len(set(ids)) != len(ids):
        print("Enter distinct, existing Grant IDs")
        return
    # Finance verifies EVERY signature/hash before including the ciphertext.
    if any(not verify_grant(grant_id, verbose=False) for grant_id in ids):
        print("Aggregation cancelled: missing or invalid/tampered grant")
        return

    n, _ = paillier_public
    combined = 1
    for grant_id in ids:
        # Multiplication of Paillier CTs means ADDITION of original amounts.
        combined = (combined * int(records[grant_id]["amount_ct"])) % (n*n)
    aggregate = {"ids": ids, "ciphertext": combined}
    print("Product of Paillier ciphertexts mod n^2(hex):", hex(combined))
    print("Selected grant signatures and MD5 hashes verified")
    print("Only the combined ciphertext will be decrypted")


def verify_and_decrypt_total():
    if aggregate is None:
        print("Aggregate grants first")
        return
    # Check again in case a record was changed after aggregation.
    if any(not verify_grant(grant_id, verbose=False) for grant_id in aggregate["ids"]):
        print("Aggregate rejected: a selected record failed verification")
        return
    print("Signatures valid; aggregate decrypted =",
          paillier_decrypt(aggregate["ciphertext"]))
    print("Finance did not decrypt individual Paillier amounts")


def role_menu(role):
    while True:
        if role == "researcher":
            choice = input("\nRESEARCHER: 1 Submit grant details | 2 View submitted details | 3 Back: ")
            if choice == "1":
                submit_grant()
            elif choice == "2":
                view_submitted()
            elif choice == "3":
                return
        elif role == "reviewer":
            choice = input("\nREVIEWER: 1 Verify | 2 Search index | 3 View decrypted hex | 4 Back: ")
            if choice == "1":
                verify_grant(input("Grant ID: ").strip().upper())
            elif choice == "2":
                search_grants()
            elif choice == "3":
                view_decrypted_hex()
            elif choice == "4":
                return
        else:
            choice = input("\nFINANCE: 1 Aggregate | 2 Verify | 3 Back: ")
            if choice == "1":
                aggregate_amounts()
            elif choice == "2":
                verify_and_decrypt_total()
            elif choice == "3":
                return
        valid = ("1", "2", "3", "4") if role == "reviewer" else ("1", "2", "3")
        if choice not in valid:
            print("Invalid choice")


while True:
    choice = input("\nMAIN: 1 Researcher | 2 Reviewer | 3 Finance Officer | 4 Exit: ")
    if choice == "1":
        role_menu("researcher")
    elif choice == "2":
        role_menu("reviewer")
    elif choice == "3":
        role_menu("finance")
    elif choice == "4":
        break
    else:
        print("Invalid choice")
