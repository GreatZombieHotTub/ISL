import re
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

aes_key = get_random_bytes(16)
search_key = get_random_bytes(32)

def encrypt(text):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(text.encode(), 16))

def decrypt(blob):
    iv, ciphertext = blob[:16], blob[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), 16).decode()

def token(word):
    return hmac.new(
        search_key, word.strip().lower().encode(), hashlib.sha256
    ).hexdigest()

documents = {
    "G001": "Grant for lab equipment",
    "G002": "Travel expenses for fieldwork",
    "G003": "Equipment maintenance report",
    "G004": "Travel budget approval",
    "G005": "Research grant proposal",
    "G006": "Conference registration costs",
    "G007": "Software license purchase",
    "G008": "Lab supplies request",
    "G009": "Fieldwork travel report",
    "G010": "Final grant expenditure",
}

encrypted_docs = {}
index = {}  # Protected search term -> encrypted document IDs

for doc_id, text in documents.items():
    encrypted_docs[doc_id] = encrypt(text)

    words = set(re.findall(r"[a-z0-9]+", text.lower()))
    words.add("grant:" + doc_id.lower())  # Also allow Grant ID search

    for word in words:
        index.setdefault(token(word), []).append(encrypt(doc_id))

query = input("Search word or grant:G001: ")
matched_ids = [decrypt(blob) for blob in index.get(token(query), [])]

print("Matching IDs:", matched_ids)

if input("View matching documents? (y/n): ").lower() == "y":
    for doc_id in matched_ids:
        print(doc_id, "->", decrypt(encrypted_docs[doc_id]))

"""
AES encrypts documents; a secret, 
repeatable search token finds matching encrypted IDs. Search travel → G002, G004, G009.
grant:G001 gives G001
"""