"""Additional Question 1: ElGamal DRM System

Implement a Python-based centralized key-management and access-control system for digital content using ElGamal. The system should:

Generate a configurable ElGamal master key pair.
Encrypt uploaded digital content.
Distribute decryption access to authorized customers.
Grant limited-time access to specific content.
Allow content creators to grant and revoke access.
Revoke and periodically renew the master key.
Securely store the private key.
Maintain audit logs of key and access operations."""

from Crypto.Util.number import getPrime, isPrime, inverse
from datetime import datetime, timedelta
import secrets


class ElGamalDRM:

    def __init__(self, key_size=512):
        self.key_size = key_size
        self.contents = {}
        self.access = {}
        self.audit_log = []
        self.master_key_revoked = False

        self.generate_master_keys()

    # ---------------- AUDIT LOG ----------------

    def log(self, operation):
        self.audit_log.append({
            "time": datetime.now(),
            "operation": operation
        })

    # ---------------- KEY GENERATION ----------------

    def generate_master_keys(self):

        # Generate p = 2q + 1
        while True:
            q = getPrime(self.key_size - 1)
            p = 2 * q + 1

            if isPrime(p):
                break

        # Find generator g
        while True:
            g = secrets.randbelow(p - 3) + 2

            if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
                break

        # Private key
        x = secrets.randbelow(p - 3) + 2

        # Public-key component
        y = pow(g, x, p)

        self.public_key = (p, g, y)
        self._private_key = x

        self.created = datetime.now()
        self.expires = self.created + timedelta(days=730)
        self.master_key_revoked = False

        self.log("MASTER_KEY_GENERATED")

    # ---------------- CONTENT ENCRYPTION ----------------

    def encrypt_content(self, creator, content_id, content):

        if self.master_key_revoked:
            raise Exception("Master key has been revoked")

        p, g, y = self.public_key
        ciphertext = []

        # Encrypt every byte using ElGamal
        for byte in content.encode():

            k = secrets.randbelow(p - 2) + 1

            c1 = pow(g, k, p)
            shared_value = pow(y, k, p)
            c2 = (byte * shared_value) % p

            ciphertext.append((c1, c2))

        self.contents[content_id] = {
            "creator": creator,
            "ciphertext": ciphertext
        }

        self.log(f"CONTENT_ENCRYPTED: {content_id}")
        print("Content encrypted:", content_id)

    # ---------------- GRANT ACCESS ----------------

    def grant_access(
        self,
        creator,
        customer,
        content_id,
        minutes
    ):

        if content_id not in self.contents:
            raise Exception("Content not found")

        if self.contents[content_id]["creator"] != creator:
            raise Exception(
                "Only the creator can grant access"
            )

        self.access[(customer, content_id)] = (
            datetime.now() + timedelta(minutes=minutes)
        )

        self.log(
            f"ACCESS_GRANTED: {customer} -> {content_id}"
        )

        print("Access granted to", customer)

    # ---------------- REVOKE ACCESS ----------------

    def revoke_access(
        self,
        creator,
        customer,
        content_id
    ):

        if self.contents[content_id]["creator"] != creator:
            raise Exception(
                "Only the creator can revoke access"
            )

        self.access.pop((customer, content_id), None)

        self.log(
            f"ACCESS_REVOKED: {customer} -> {content_id}"
        )

        print("Access revoked for", customer)

    # ---------------- CONTENT DECRYPTION ----------------

    def access_content(self, customer, content_id):

        if self.master_key_revoked:
            raise Exception("Master key has been revoked")

        permission = (customer, content_id)

        if permission not in self.access:
            raise Exception("Customer has no access")

        if datetime.now() > self.access[permission]:
            raise Exception("Access has expired")

        p, g, y = self.public_key
        ciphertext = self.contents[content_id]["ciphertext"]

        decrypted_bytes = []

        for c1, c2 in ciphertext:

            shared_value = pow(
                c1,
                self._private_key,
                p
            )

            shared_inverse = inverse(
                shared_value,
                p
            )

            byte = (c2 * shared_inverse) % p
            decrypted_bytes.append(byte)

        plaintext = bytes(decrypted_bytes).decode()

        self.log(
            f"CONTENT_ACCESSED: {customer} -> {content_id}"
        )

        return plaintext

    # ---------------- MASTER KEY CONTROL ----------------

    def revoke_master_key(self):
        self.master_key_revoked = True
        self.log("MASTER_KEY_REVOKED")
        print("Master key revoked")

    def renew_master_key(self):
        self.generate_master_keys()
        self.log("MASTER_KEY_RENEWED")
        print("Master key renewed")

    def check_key_expiry(self):
        if datetime.now() >= self.expires:
            self.renew_master_key()

    # ---------------- AUDIT REPORT ----------------

    def show_audit_log(self):

        print("\n========== AUDIT LOG ==========")

        for entry in self.audit_log:
            print(
                entry["time"],
                "|",
                entry["operation"]
            )


# =================================================
# MAIN PROGRAM
# =================================================

# Use 2048 for the requested key size.
# Using 512 makes the lab demonstration faster.
drm = ElGamalDRM(key_size=512)

# Creator uploads content
drm.encrypt_content(
    creator="Alice",
    content_id="BOOK101",
    content="This is a protected digital book."
)

# Alice gives Bob access for 30 minutes
drm.grant_access(
    creator="Alice",
    customer="Bob",
    content_id="BOOK101",
    minutes=30
)

# Bob accesses and decrypts the content
decrypted = drm.access_content(
    customer="Bob",
    content_id="BOOK101"
)

print("\nDecrypted Content:", decrypted)

# Alice revokes Bob's access
drm.revoke_access(
    creator="Alice",
    customer="Bob",
    content_id="BOOK101"
)

# Bob tries again
try:
    drm.access_content("Bob", "BOOK101")
except Exception as error:
    print("Access denied:", error)

drm.check_key_expiry()
drm.show_audit_log()
