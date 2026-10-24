import re
import math
import secrets
import hashlib
from Crypto.Util.number import getPrime

def generate_keys():
    while True:
        p, q = getPrime(64), getPrime(64)
        if p != q:
            n = p * q
            lam = math.lcm(p - 1, q - 1)
            if math.gcd(lam, n) == 1:
                return (n, n + 1), (lam, pow(lam, -1, n))

def encrypt(m, public_key):
    n, g = public_key
    if not 0 <= m < n:
        raise ValueError("Number is too large for this key")

    while True:
        r = secrets.randbelow(n - 1) + 1
        if math.gcd(r, n) == 1:
            break

    return (pow(g, m, n*n) * pow(r, n, n*n)) % (n*n)

def decrypt(c, public_key, private_key):
    n, _ = public_key
    lam, mu = private_key
    return (((pow(c, lam, n*n) - 1) // n) * mu) % n

def word_number(word):
    # Turn a word into a number Paillier can encrypt.
    word = word.strip().lower()
    return int.from_bytes(
        hashlib.sha256(word.encode()).digest()[:8], "big"
    )

documents = {
    1: "Grant for lab equipment",
    2: "Travel expenses for fieldwork",
    3: "Equipment maintenance report",
    4: "Travel budget approval",
    5: "Research grant proposal",
    6: "Conference registration costs",
    7: "Software license purchase",
    8: "Lab supplies request",
    9: "Fieldwork travel report",
    10: "Final grant expenditure",
}

public_key, private_key = generate_keys()

# First build: word -> document IDs
index = {}
for doc_id, text in documents.items():
    for word in set(re.findall(r"[a-z0-9]+", text.lower())):
        index.setdefault(word, []).append(doc_id)

# Encrypt both the index words and their document IDs.
encrypted_index = []
for word, ids in index.items():
    encrypted_index.append((
        encrypt(word_number(word), public_key),
        [encrypt(doc_id, public_key) for doc_id in ids]
    ))

query = input("Search word: ")
encrypted_query = encrypt(word_number(query), public_key)
n = public_key[0]
matched_ids = []

for encrypted_word, encrypted_ids in encrypted_index:
    # Encrypted word - encrypted query
    encrypted_difference = (
        encrypted_word * pow(encrypted_query, -1, n*n)
    ) % (n*n)

    # Difference zero means the words match.
    if decrypt(encrypted_difference, public_key, private_key) == 0:
        matched_ids.extend(
            decrypt(enc_id, public_key, private_key)
            for enc_id in encrypted_ids
        )

print("Matching IDs:", [f"G{i:03d}" for i in sorted(set(matched_ids))])

for i in sorted(set(matched_ids)):
    print(f"G{i:03d} -> {documents[i]}")

"""
Q2 = Paillier-based encrypted index: 
Paillier encryption is random, so encrypting travel twice gives different ciphertexts

For the big exam questions: use the Q1 index idea to find grant:G001 or constituency:101. Use Paillier from 
Lab 7 to add encrypted amounts or votes. Q2 is the manual’s separate Paillier-search exercise; don’t confuse its search calculation with Paillier tallying.
"""