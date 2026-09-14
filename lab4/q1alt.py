from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


# ============================================================
# KEY MANAGEMENT SYSTEM
# ============================================================

class KeyManagementSystem:

    def __init__(self):
        self.systems = {}
        self.revoked = set()

        # Common public DH parameters
        print("Generating Diffie-Hellman parameters...")
        self.dh_parameters = dh.generate_parameters(
            generator=2,
            key_size=2048
        )

    def generate_keys(self, system_name):

        # RSA key pair
        rsa_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Diffie-Hellman key pair
        dh_private = self.dh_parameters.generate_private_key()
        dh_public = dh_private.public_key()

        self.systems[system_name] = {
            "rsa_private": rsa_private,
            "rsa_public": rsa_private.public_key(),
            "dh_private": dh_private,
            "dh_public": dh_public
        }

        self.revoked.discard(system_name)

        print("Keys generated for", system_name)

    def get_keys(self, system_name):

        if system_name in self.revoked:
            raise Exception("Keys have been revoked")

        if system_name not in self.systems:
            raise Exception("System does not exist")

        return self.systems[system_name]

    def revoke_keys(self, system_name):

        if system_name in self.systems:
            self.revoked.add(system_name)
            print("Keys revoked for", system_name)


# ============================================================
# AES KEY DERIVATION
# ============================================================

def derive_aes_key(shared_secret, salt):

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        info=b"SecureCorp Communication"
    ).derive(shared_secret)


# ============================================================
# SEND DOCUMENT
# ============================================================

def send_document(kms, sender_name, receiver_name, message):

    sender = kms.get_keys(sender_name)
    receiver = kms.get_keys(receiver_name)

    # Sender calculates DH shared secret
    sender_shared_secret = sender["dh_private"].exchange(
        receiver["dh_public"]
    )

    # Generate salt and derive AES key
    salt = os.urandom(16)

    sender_aes_key = derive_aes_key(
        sender_shared_secret,
        salt
    )

    # Encrypt document using AES
    nonce = os.urandom(12)
    aes = AESGCM(sender_aes_key)

    ciphertext = aes.encrypt(
        nonce,
        message.encode(),
        None
    )

    # Protect salt using receiver's RSA public key
    encrypted_salt = receiver["rsa_public"].encrypt(
        salt,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("\nDocument sent from", sender_name)
    print("Document sent to  ", receiver_name)

    return encrypted_salt, nonce, ciphertext


# ============================================================
# RECEIVE DOCUMENT
# ============================================================

def receive_document(
    kms,
    sender_name,
    receiver_name,
    encrypted_salt,
    nonce,
    ciphertext
):

    sender = kms.get_keys(sender_name)
    receiver = kms.get_keys(receiver_name)

    # Receiver recovers salt using RSA private key
    salt = receiver["rsa_private"].decrypt(
        encrypted_salt,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Receiver calculates the same DH shared secret
    receiver_shared_secret = receiver["dh_private"].exchange(
        sender["dh_public"]
    )

    # Receiver derives the same AES key
    receiver_aes_key = derive_aes_key(
        receiver_shared_secret,
        salt
    )

    # Decrypt document
    aes = AESGCM(receiver_aes_key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode()


# ============================================================
# MAIN PROGRAM
# ============================================================

kms = KeyManagementSystem()

systems = [
    "Finance System (A)",
    "HR System (B)",
    "Supply Chain System (C)"
]

# Generate keys for all systems
for system in systems:
    kms.generate_keys(system)


# Finance sends a document to HR
message = "Confidential Financial Report"

encrypted_salt, nonce, ciphertext = send_document(
    kms,
    "Finance System (A)",
    "HR System (B)",
    message
)

print("Original Message :", message)
print("Ciphertext       :", ciphertext.hex())

decrypted_message = receive_document(
    kms,
    "Finance System (A)",
    "HR System (B)",
    encrypted_salt,
    nonce,
    ciphertext
)

print("Decrypted Message:", decrypted_message)


# ============================================================
# KEY REVOCATION
# ============================================================

print("\n--- Key Revocation ---")

kms.revoke_keys("HR System (B)")

try:
    kms.get_keys("HR System (B)")
except Exception as error:
    print("Access denied:", error)


# ============================================================
# ADDING A NEW SYSTEM
# ============================================================

print("\n--- Adding New Subsystem ---")

kms.generate_keys("Research System (D)")
