"""Menu-driven e-voting lab program. Run with pycryptodome installed.

Story: the voter locks and signs a ballot; the server checks it without
decrypting the vote number; the tally authority combines encrypted votes.
"""

"""ORIGINAL SAMPLE QUESTION 1: ELECTRONIC VOTING

OBJECTIVES (what the question wants):
1. Voter enters a ballot ID, candidate number, and constituency.
2. Hash the ORIGINAL ballot with SHA-512 before encryption.
3. Encrypt the ballot with AES-256 in CBC mode; wrap its AES key with the
   Election Commission's RSA-4096 public key (OAEP).
4. Sign the ballot hash with the voter's ElGamal private key.
5. Encrypt vote numbers with Paillier so encrypted votes can be counted.
6. Server checks the signature, hash, and voting time; search ballots by
   constituency and time using an encrypted search index.
7. Tally authority adds encrypted votes per candidate and reveals only the
   final candidate totals after both approval shares are supplied.
8. Offer separate Voter, Server, and Tally menus and print each result.

METHODS USED: SHA-512 | AES-256-CBC | RSA-4096-OAEP | ElGamal signature |
Paillier addition | encrypted search index | two-share tally approval.

PRACTICE INPUT: B001 and B002 vote for candidate 1 -> candidate 1 gets 2.
Set REPRODUCE_SAMPLE = True below for the sample's fixed AES/Paillier values.

This is one local program: it has no sockets. Its keys and votes live in
memory until it closes. Time is taken from the local clock; the two shares
simulate approval within one process. Run with pycryptodome installed.
"""


import hashlib
import hmac
import math
import secrets
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime


# FIXED-OUTPUT PRACTICE: switch to True to reproduce the sample's AES and
# Paillier values for B001/B002. Leave False for fresh random values.
# These values are supplied by the sample, not good defaults for real voting.
REPRODUCE_SAMPLE = False
SAMPLE_AES_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)
SAMPLE_IVS = {
    "B001": bytes.fromhex("202122232425262728292a2b2c2d2e2f"),
    "B002": bytes.fromhex("303132333435363738393a3b3c3d3e3f"),
}
SAMPLE_PAILLIER_R = {"B001": 2, "B002": 3}


# STEP 0: Set up all keys once, before anyone votes.
# The start/end times are relative so you can run this program on any day.
IST = ZoneInfo("Asia/Kolkata")
now = datetime.now(IST)
VOTING_START = now - timedelta(hours=1)
VOTING_END = now + timedelta(hours=2)
CANDIDATES = (1, 2, 3)

print("Generating RSA-4096 keys; please wait...")
rsa_private = RSA.generate(4096)          # Election Commission keeps this secret
rsa_public = rsa_private.publickey()     # Voters receive this public key

# ElGamal signature keys (small lab values, like your Lab 6 code).
EL_P, EL_G = 467, 2
voter_private = secrets.randbelow(EL_P - 2) + 1
voter_public = pow(EL_G, voter_private, EL_P)


def make_paillier_keys():
    # The sample uses n=3127=53*59 and g=n+1. Otherwise make larger primes.
    if REPRODUCE_SAMPLE:
        p, q = 53, 59
        n = p * q
        lam = math.lcm(p - 1, q - 1)
        return (n, n + 1), lam
    while True:
        p, q = getPrime(256), getPrime(256)
        if p != q:
            n = p * q
            lam = math.lcm(p - 1, q - 1)
            if math.gcd(lam, n) == 1:
                return (n, n + 1), lam


paillier_public, paillier_lambda = make_paillier_keys()


# Split the private number into two pieces. Neither piece works alone.
# This simulates threshold approval inside one program; a real distributed
# threshold-decryption protocol would never reconstruct the key in one place.
share_modulus = getPrime(600)
share_a = secrets.randbelow(share_modulus)
share_b = (paillier_lambda - share_a) % share_modulus
del paillier_lambda

index_key = get_random_bytes(32)
index_aes_key = get_random_bytes(16)
records = {}                 # Ballot ID -> encrypted, signed record
search_index = {}            # Protected search term -> encrypted ballot IDs
aggregate = None


# STEP 1: The voter hashes and signs the ballot (Labs 5 + 6).
# The hash is a fingerprint of the ORIGINAL readable ballot, not ciphertext.
def sign_digest(digest):
    h = int.from_bytes(digest, "big") % (EL_P - 1)
    while True:
        k = secrets.randbelow(EL_P - 2) + 1
        if math.gcd(k, EL_P - 1) == 1:
            break
    r = pow(EL_G, k, EL_P)
    s = ((h - voter_private * r) * pow(k, -1, EL_P - 1)) % (EL_P - 1)
    return r, s


def signature_valid(digest, signature, public_key):
    # Server: use the voter's PUBLIC key to check the signature.
    r, s = signature
    if not (0 < r < EL_P and 0 <= s < EL_P - 1):
        return False
    h = int.from_bytes(digest, "big") % (EL_P - 1)
    return pow(EL_G, h, EL_P) == (
        pow(public_key, r, EL_P) * pow(r, s, EL_P)
    ) % EL_P


# STEP 2: AES locks the ballot; RSA locks the AES key (Labs 2 + 3).
# CBC needs a fresh 16-byte IV. A supplied IV is only for fixed-output tests.
def aes_encrypt(data, key, iv=None):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.iv, cipher.encrypt(pad(data, AES.block_size))


def aes_decrypt(iv, ciphertext, key):
    # Receiver must use the SAME key and IV used for this ciphertext.
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


# STEP 3: Paillier locks numbers but still allows their encrypted sums (Lab 7).
def paillier_encrypt(number, chosen_r=None):
    n, g = paillier_public
    if chosen_r is None:
        while True:
            random_r = secrets.randbelow(n - 1) + 1
            if math.gcd(random_r, n) == 1:
                break
    else:
        if not 1 <= chosen_r < n or math.gcd(chosen_r, n) != 1:
            raise ValueError("Paillier randomness must be coprime to n")
        random_r = chosen_r
    return (pow(g, number, n*n) * pow(random_r, n, n*n)) % (n*n)


def paillier_decrypt(ciphertext, lam):
    # Used only on COMBINED totals, never on an individual vote.
    n, _ = paillier_public
    mu = pow(lam, -1, n)
    value = (pow(ciphertext, lam, n*n) - 1) // n
    return (value * mu) % n


# STEP 4: Keep a protected lookup so searches do not open ballots (Lab 8).
def search_token(term):
    # Same term + secret index key -> same token, so exact lookup works.
    return hmac.new(index_key, term.lower().encode(), hashlib.sha256).hexdigest()


def add_to_index(term, ballot_id):
    # The token is the lookup key; even its list of ballot IDs is AES-encrypted.
    iv, ciphertext = aes_encrypt(ballot_id.encode(), index_aes_key)
    search_index.setdefault(search_token(term), []).append((iv, ciphertext))


def find_ids(term):
    encrypted_ids = search_index.get(search_token(term), [])
    return {
        aes_decrypt(iv, ciphertext, index_aes_key).decode()
        for iv, ciphertext in encrypted_ids
    }


def cast_vote():
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

    # First make the ballot text. These exact bytes are hashed and encrypted.
    ballot = f"CandidateID={candidate};ConstituencyID={constituency}".encode()
    digest = SHA512.new(ballot).digest()

    # AES encrypts the BALLOT; RSA encrypts only its 32-byte AES key.
    aes_key = SAMPLE_AES_KEY if REPRODUCE_SAMPLE else get_random_bytes(32)
    fixed_iv = SAMPLE_IVS.get(ballot_id) if REPRODUCE_SAMPLE else None
    iv, ciphertext = aes_encrypt(ballot, aes_key, fixed_iv)
    wrapped_key = PKCS1_OAEP.new(rsa_public).encrypt(aes_key)
    # The voter's ElGamal PRIVATE key signs the ballot's SHA-512 fingerprint.
    signature = sign_digest(digest)

    # The question asks to encrypt the numerical candidate ID itself.
    # Fixed r=2 or 3 reproduces the sample's two printed Paillier ciphertexts.
    fixed_r = SAMPLE_PAILLIER_R.get(ballot_id) if REPRODUCE_SAMPLE else None
    candidate_ct = paillier_encrypt(candidate, fixed_r)
    # For genuine vote COUNTS, give each candidate an encrypted 1 or 0.
    # Reuse the candidate-ID ciphertext for candidate 1 when its ID is 1.
    count_ct = {
        c: (candidate_ct if c == candidate == 1 else paillier_encrypt(int(c == candidate)))
        for c in CANDIDATES
    }
    timestamp = datetime.now(IST)      # Server-clock timestamp for this program

    records[ballot_id] = {
        "iv": iv, "ciphertext": ciphertext, "wrapped_key": wrapped_key,
        "hash": digest, "signature": signature,
        "voter_public": voter_public, "candidate_ct": candidate_ct,
        "count_ct": count_ct, "timestamp": timestamp, "accepted": False,
    }
    # Index only the constituency and time; never index the candidate choice.
    add_to_index(f"constituency:{constituency}", ballot_id)
    add_to_index("time:" + timestamp.strftime("%Y-%m-%d %H:%M"), ballot_id)

    print("Ballot UTF-8:", ballot.decode())
    print("SHA-512(hex):", digest.hex())
    print("IV(hex):", iv.hex())
    print("AES-256-CBC CT(hex):", ciphertext.hex())
    print("RSA-4096 wrapped AES key:", wrapped_key.hex()[:64] + "...", f"({len(wrapped_key)} bytes)")
    print("ElGamal signature (r, s):", signature)
    print("Paillier candidate ID CT(hex):", hex(candidate_ct))
    for c in CANDIDATES:
        print(f"Paillier candidate-{c} count CT(hex):", hex(count_ct[c]))
    print("Timestamp:", timestamp.strftime("%d-%m-%Y %H:%M:%S IST"))
    print(ballot_id, "submitted; constituency/time indexed")


def verify_ballot(ballot_id, verbose=True):
    record = records.get(ballot_id)
    if record is None:
        if verbose:
            print("Ballot not found")
        return False
    try:
        # RSA unwraps the AES key. AES then opens the ballot, not the vote CT.
        aes_key = PKCS1_OAEP.new(rsa_private).decrypt(record["wrapped_key"])
        ballot = aes_decrypt(record["iv"], record["ciphertext"], aes_key)
        # Recompute the fingerprint and verify the voter's signature on it.
        digest = SHA512.new(ballot).digest()
        hash_ok = hmac.compare_digest(digest, record["hash"])
        sign_ok = signature_valid(digest, record["signature"], record["voter_public"])
        time_ok = VOTING_START <= record["timestamp"] <= VOTING_END
    except (ValueError, KeyError, TypeError):
        hash_ok = sign_ok = time_ok = False

    record["accepted"] = hash_ok and sign_ok and time_ok
    if verbose:
        print("RSA unwrap and AES decrypt:", "OK" if hash_ok else "FAILED")
        print("SHA-512 hash:", "matches" if hash_ok else "MISMATCH")
        print("ElGamal signature:", "valid" if sign_ok else "INVALID")
        print("Timestamp:", "within period" if time_ok else "INVALID")
        print(ballot_id, "accepted" if record["accepted"] else "rejected")
    return record["accepted"]


def search_ballots():
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
                # Look up each minute token; do not decrypt ballots to search.
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


def aggregate_votes():
    global aggregate
    ids = [s.strip().upper() for s in input("Ballot IDs, comma-separated: ").split(",")]
    if not ids or len(set(ids)) != len(ids) or any(not verify_ballot(b, False) for b in ids):
        print("Invalid, repeated, or unverified ballot ID")
        return

    n, _ = paillier_public
    aggregate = {candidate: 1 for candidate in CANDIDATES}
    for ballot_id in ids:
        for candidate in CANDIDATES:
            # Paillier: multiplying encrypted 0/1 values adds their votes.
            aggregate[candidate] = (
                aggregate[candidate] * records[ballot_id]["count_ct"][candidate]
            ) % (n*n)

    for candidate in CANDIDATES:
        print(f"Candidate {candidate} combined CT(hex): {hex(aggregate[candidate])}")
    print("Only combined ciphertexts will be decrypted")


def threshold_decrypt():
    if aggregate is None:
        print("Aggregate the ballots first")
        return

    # Reconstruct the Paillier private value from both shares, then decrypt
    # ONLY aggregate ciphertexts. No individual vote is decrypted here.
    lam = (share_a + share_b) % share_modulus
    print("Two authority shares combined")
    for candidate, ciphertext in aggregate.items():
        print(f"Candidate {candidate} total:", paillier_decrypt(ciphertext, lam))
    print("Individual votes were not decrypted")


def role_menu(role):
    while True:
        if role == "voter":
            choice = input("\nVOTER: 1 Cast vote | 2 Back: ")
            if choice == "1":
                cast_vote()
            elif choice == "2":
                return
        elif role == "server":
            choice = input("\nSERVER: 1 Verify | 2 Search | 3 Back: ")
            if choice == "1":
                verify_ballot(input("Ballot ID: ").strip().upper())
            elif choice == "2":
                search_ballots()
            elif choice == "3":
                return
        else:
            choice = input("\nTALLY: 1 Aggregate | 2 Threshold decrypt | 3 Back: ")
            if choice == "1":
                aggregate_votes()
            elif choice == "2":
                threshold_decrypt()
            elif choice == "3":
                return
        if choice not in (("1", "2") if role == "voter" else ("1", "2", "3")):
            print("Invalid choice")


while True:
    choice = input("\nMAIN: 1 Voter | 2 Election Server | 3 Tally Authority | 4 Exit: ")
    if choice == "1":
        role_menu("voter")
    elif choice == "2":
        role_menu("server")
    elif choice == "3":
        role_menu("tally")
    elif choice == "4":
        break
    else:
        print("Invalid choice")
