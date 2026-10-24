"""Campus election: fixed-method, menu-driven lab program.

Install in Colab: !pip install pycryptodome

METHODS USED
1. SHA-256: hash the ORIGINAL readable ballot before encryption (32-byte hash).
2. Schnorr: sign that hash with the voter's private key; server verifies with public key.
   p=23, q=11, g=4 are tiny LAB values, not real security parameters.
3. AES-192-CTR: encrypt ballot text with a NEW 24-byte AES key per ballot.
   AES has 16-byte blocks; CTR uses a nonce and needs NO padding.
4. RSA-2048 OAEP: encrypt only the AES key using the server's public key.
5. Paillier: encrypt candidate ID, plus 1/0 vote counts; add encrypted counts.
6. Lab 8 index: HMAC-SHA256 lookup tokens, AES-CBC-encrypted ballot IDs.
7. Server-clock timestamp (IST); two-share tally is a classroom simulation.

Valid candidates are 1, 2, 3. Any number of voters may submit, including TWO.
Example: B101 votes for 2, B102 votes for 1 -> totals 1, 1, 0.
No sockets: client/server/tally are separate menus in this one program.
"""

import hashlib
import hmac
import json
import math
import secrets
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime


# STEP 0: Generate keys and prepare storage once.
CANDIDATES = (1, 2, 3)
IST = ZoneInfo("Asia/Kolkata")
now = datetime.now(IST)
VOTING_START, VOTING_END = now - timedelta(hours=1), now + timedelta(hours=2)

print("Generating RSA-2048 and Paillier keys; please wait...")
rsa_private = RSA.generate(2048)
rsa_public = rsa_private.publickey()

SN_P, SN_Q, SN_G = 23, 11, 4
voter_private = secrets.randbelow(SN_Q - 1) + 1
voter_public = pow(SN_G, voter_private, SN_P)

p, q = getPrime(256), getPrime(256)
while p == q:
    q = getPrime(256)

n = p * q
paillier_public = (n, n + 1)
private_lambda = math.lcm(p - 1, q - 1)

# Classroom simulation of two authority shares.
share_modulus = getPrime(600)
share_a = secrets.randbelow(share_modulus)
share_b = (private_lambda - share_a) % share_modulus
del private_lambda

index_key = get_random_bytes(32)
index_aes_key = get_random_bytes(16)

records = {}
search_index = {}
aggregate = None


# STEP 1: Sign and verify a SHA-256 hash with Schnorr.
def schnorr_sign(digest):
    k = secrets.randbelow(SN_Q - 1) + 1
    r = pow(SN_G, k, SN_P)

    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, "big")
    e = int.from_bytes(
        SHA256.new(digest + r_bytes).digest(), "big"
    ) % SN_Q

    s = (k + voter_private * e) % SN_Q
    return (e, s)


def schnorr_valid(digest, signature):
    e, s = signature

    if not (0 <= e < SN_Q and 0 <= s < SN_Q):
        return False

    y_to_e = pow(voter_public, e, SN_P)
    r = (pow(SN_G, s, SN_P) * pow(y_to_e, -1, SN_P)) % SN_P

    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, "big")
    expected = int.from_bytes(
        SHA256.new(digest + r_bytes).digest(), "big"
    ) % SN_Q

    return e == expected


# STEP 2: AES encrypts the ballot; RSA encrypts only the AES key.
def aes_encrypt(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CTR)
    return cipher.nonce, cipher.encrypt(data)


def aes_decrypt(nonce, ciphertext, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)


# STEP 3: Paillier encrypts numbers and adds encrypted vote counts.
def paillier_encrypt(number):
    while True:
        r = secrets.randbelow(n - 1) + 1
        if math.gcd(r, n) == 1:
            break

    return (
        pow(n + 1, number, n * n) *
        pow(r, n, n * n)
    ) % (n * n)


def paillier_add(ciphertexts):
    combined = 1

    for ciphertext in ciphertexts:
        combined = combined * ciphertext % (n * n)

    return combined


# STEP 4: Search using an index without opening the ballot text.
def search_token(term):
    return hmac.new(
        index_key,
        term.upper().encode(),
        hashlib.sha256
    ).hexdigest()


def add_to_index(term, ballot_id):
    cipher = AES.new(index_aes_key, AES.MODE_CBC)
    encrypted_id = cipher.encrypt(pad(ballot_id.encode(), 16))

    search_index.setdefault(
        search_token(term), []
    ).append((cipher.iv, encrypted_id))


def find_ids(term):
    ids = set()

    for iv, ciphertext in search_index.get(search_token(term), []):
        cipher = AES.new(index_aes_key, AES.MODE_CBC, iv)
        ballot_id = unpad(cipher.decrypt(ciphertext), 16).decode()
        ids.add(ballot_id)

    return ids


def package_bytes(ballot_id, record):
    # A second signature protects the encrypted vote counts and timestamp.
    fields = {
        "id": ballot_id,
        "nonce": record["nonce"],
        "ciphertext": record["ciphertext"],
        "wrapped_key": record["wrapped_key"],
        "candidate_ct": record["candidate_ct"],
        "counts_ct": record["counts_ct"],
        "timestamp": record["timestamp"]
    }

    return json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":")
    ).encode()


# STEP 5A: CLIENT submits a ballot.
def client_submit():
    ballot_id = input("Ballot ID: ").strip().upper()

    if not ballot_id or ballot_id in records:
        print("Invalid or duplicate Ballot ID")
        return

    try:
        candidate = int(input("Candidate ID (1/2/3): "))
        constituency = int(input("Constituency ID: "))

        if candidate not in CANDIDATES or constituency <= 0:
            raise ValueError

    except ValueError:
        print("Invalid candidate or constituency")
        return

    # First create and hash the ORIGINAL ballot.
    ballot = (
        f"CandidateID={candidate};"
        f"ConstituencyID={constituency}"
    ).encode()

    digest = SHA256.new(ballot).digest()
    signature = schnorr_sign(digest)

    # AES-192-CTR encrypts the ballot.
    aes_key = get_random_bytes(24)
    nonce, ciphertext = aes_encrypt(ballot, aes_key)

    # RSA-2048 encrypts only the AES key.
    wrapped_key = PKCS1_OAEP.new(rsa_public).encrypt(aes_key)

    # Encrypt the candidate number itself.
    candidate_ct = paillier_encrypt(candidate)

    # For vote FREQUENCY: chosen candidate gets encrypted 1;
    # the other candidates get encrypted 0.
    counts_ct = {
        str(c): paillier_encrypt(int(c == candidate))
        for c in CANDIDATES
    }

    timestamp = datetime.now(IST)

    record = {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "wrapped_key": wrapped_key.hex(),
        "hash": digest.hex(),
        "signature": signature,
        "candidate_ct": str(candidate_ct),
        "counts_ct": {
            c: str(ct) for c, ct in counts_ct.items()
        },
        "timestamp": timestamp.isoformat()
    }

    package_digest = SHA256.new(
        package_bytes(ballot_id, record)
    ).digest()

    record["package_signature"] = schnorr_sign(package_digest)
    records[ballot_id] = record

    add_to_index(f"constituency:{constituency}", ballot_id)
    add_to_index(
        "time:" + timestamp.strftime("%Y-%m-%d %H:%M"),
        ballot_id
    )

    print("Ballot UTF-8:", ballot.decode())
    print("SHA-256(hex):", digest.hex())
    print("AES-192-CTR nonce(hex):", nonce.hex())
    print("AES-192-CTR CT(hex):", ciphertext.hex())
    print(
        "RSA-2048 wrapped AES key(hex):",
        wrapped_key.hex()[:64] + "..."
    )
    print("Schnorr signature (e, s):", signature)
    print("Paillier candidate ID CT(hex):", hex(candidate_ct))

    for c in CANDIDATES:
        print(
            f"Candidate {c} encrypted count(hex):",
            hex(counts_ct[str(c)])
        )

    print("Timestamp:", timestamp.strftime("%d-%m-%Y %H:%M:%S IST"))
    print(ballot_id, "submitted")


# STEP 5B: SERVER verifies the ballot.
def server_verify(ballot_id, verbose=True):
    record = records.get(ballot_id)

    if record is None:
        if verbose:
            print("Ballot not found")
        return False

    try:
        # RSA opens the AES key; AES opens the ballot.
        aes_key = PKCS1_OAEP.new(rsa_private).decrypt(
            bytes.fromhex(record["wrapped_key"])
        )

        ballot = aes_decrypt(
            bytes.fromhex(record["nonce"]),
            bytes.fromhex(record["ciphertext"]),
            aes_key
        )

        # Recalculate SHA-256 from the recovered original ballot.
        digest = SHA256.new(ballot).digest()

        hash_ok = hmac.compare_digest(
            digest,
            bytes.fromhex(record["hash"])
        )

        signature_ok = schnorr_valid(
            digest,
            record["signature"]
        )

        package_digest = SHA256.new(
            package_bytes(ballot_id, record)
        ).digest()

        package_ok = schnorr_valid(
            package_digest,
            record["package_signature"]
        )

        timestamp = datetime.fromisoformat(record["timestamp"])
        time_ok = VOTING_START <= timestamp <= VOTING_END

        ciphertexts = [int(record["candidate_ct"])] + [
            int(record["counts_ct"][str(c)])
            for c in CANDIDATES
        ]

        counts_ok = all(
            0 < ct < n * n and math.gcd(ct, n) == 1
            for ct in ciphertexts
        )

    except (ValueError, TypeError, KeyError, OverflowError):
        hash_ok = False
        signature_ok = False
        package_ok = False
        time_ok = False
        counts_ok = False

    valid = (
        hash_ok and signature_ok and
        package_ok and time_ok and counts_ok
    )

    if verbose:
        print("SHA-256 hash:", "matches" if hash_ok else "MISMATCH")
        print(
            "Schnorr signature:",
            "valid" if signature_ok else "INVALID"
        )
        print(
            "Encrypted fields signature:",
            "valid" if package_ok else "INVALID"
        )
        print(
            "Timestamp:",
            "within period" if time_ok else "INVALID"
        )
        print(ballot_id, "accepted" if valid else "rejected")

    return valid


def server_search():
    choice = input("Search 1 Constituency / 2 Time range: ").strip()

    if choice == "1":
        constituency = input("Constituency ID: ").strip()
        ids = find_ids("constituency:" + constituency)

    elif choice == "2":
        try:
            start = datetime.strptime(
                input("From (HH:MM): "), "%H:%M"
            )
            end = datetime.strptime(
                input("To (HH:MM): "), "%H:%M"
            )

            if end < start:
                raise ValueError

            day = datetime.now(IST).strftime("%Y-%m-%d")
            ids = set()

            while start <= end:
                term = "time:" + day + " " + start.strftime("%H:%M")
                ids |= find_ids(term)
                start += timedelta(minutes=1)

        except ValueError:
            print("Invalid time range; use HH:MM for today")
            return

    else:
        print("Invalid choice")
        return

    print("Matching ballot IDs:", ", ".join(sorted(ids)) or "None")
    print("Ballot contents remain encrypted")


# STEP 6A: TALLY combines encrypted 1/0 counts.
def tally_task():
    global aggregate
    aggregate = None

    ids = [
        x.strip().upper()
        for x in input("Ballot IDs, comma-separated: ").split(",")
    ]

    if (
        not ids or
        any(not x for x in ids) or
        len(set(ids)) != len(ids) or
        len(ids) >= n or
        any(not server_verify(x, False) for x in ids)
    ):
        print("Invalid, repeated, or unverified ballot ID")
        return

    combined = {
        str(c): paillier_add([
            int(records[ballot_id]["counts_ct"][str(c)])
            for ballot_id in ids
        ])
        for c in CANDIDATES
    }

    aggregate = {"ids": ids, "combined": combined}

    for c in CANDIDATES:
        print(
            f"Candidate {c} combined CT(hex):",
            hex(combined[str(c)])
        )

    print("Only the combined ciphertexts will be decrypted")


def task_decrypt_total():
    if aggregate is None:
        print("Aggregate ballots first")
        return

    if any(
        not server_verify(x, False)
        for x in aggregate["ids"]
    ):
        print("Aggregate rejected: a ballot failed verification")
        return

    # Both shares are needed to reconstruct the private value.
    private_lambda = (share_a + share_b) % share_modulus
    mu = pow(private_lambda, -1, n)

    print("Two authority shares combined")

    for c in CANDIDATES:
        combined = aggregate["combined"][str(c)]

        total = (
            ((pow(combined, private_lambda, n * n) - 1) // n)
            * mu
        ) % n

        print(f"Candidate {c} total:", total)

    print("Individual votes were not decrypted")


# STEP 6B: Menu if-statements are needed for the exam's role menus.
def role_menu(role):
    while True:
        if role == "client":
            choice = input("\nCLIENT: 1 Cast vote | 2 Back: ")

            if choice == "1":
                client_submit()
            elif choice == "2":
                return

        elif role == "server":
            choice = input(
                "\nSERVER: 1 Verify | 2 Search index | 3 Back: "
            )

            if choice == "1":
                ballot_id = input("Ballot ID: ").strip().upper()
                server_verify(ballot_id)
            elif choice == "2":
                server_search()
            elif choice == "3":
                return

        else:
            choice = input(
                "\nTALLY: 1 Aggregate | 2 Decrypt final totals | 3 Back: "
            )

            if choice == "1":
                tally_task()
            elif choice == "2":
                task_decrypt_total()
            elif choice == "3":
                return

        valid = (
            ("1", "2") if role == "client"
            else ("1", "2", "3")
        )

        if choice not in valid:
            print("Invalid choice")


if __name__ == "__main__":
    while True:
        choice = input(
            "\nMAIN: 1 Client | 2 Server | 3 Tally | 4 Exit: "
        )

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