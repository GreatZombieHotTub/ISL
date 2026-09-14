"""question 1: medsecure

develop a secure medical record management system called medsecure.

patient encrypts the complete medical-record file using aes-256.
patient creates a sha-256 hash and signs it using elgamal.
doctor decrypts the complete file, checks its hash, and verifies its signature.
admin can only see the encrypted file’s hash and verify its signature.
use a menu to select patient, doctor, admin, or exit.

algorithms used:

aes-256 encryption
sha-256 hashing
elgamal digital signature"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from math import gcd
import secrets


# aes-256 key shared by the patient and doctor
aes_key = b"0123456789abcdef0123456789abcdef"

# create a file containing two medical records
medical_data = """patient id: 101
name: aman
blood group: a+
diagnosis: fever

patient id: 102
name: riya
blood group: b+
diagnosis: allergy"""

with open("medical_records.txt", "w") as file:
    file.write(medical_data)


# small elgamal values used only for demonstration
p = 467
g = 2
x = secrets.randbelow(p - 2) + 1
y = pow(g, x, p)

# this stores one uploaded file while the program runs
uploaded_file = []


def create_signature(message):
    # convert the sha-256 hash into an integer
    h = int.from_bytes(SHA256.new(message).digest(), "big") % (p - 1)

    # choose k that has an inverse modulo p - 1
    while True:
        k = secrets.randbelow(p - 2) + 1
        if gcd(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    k_inverse = pow(k, -1, p - 1)
    s = ((h - x * r) * k_inverse) % (p - 1)
    return r, s


def verify_signature(message, r, s):
    h = int.from_bytes(SHA256.new(message).digest(), "big") % (p - 1)
    left = pow(g, h, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right


def patient_menu():
    # read and encrypt the complete medical file
    with open("medical_records.txt", "r") as file:
        record = file.read()

    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded_record = pad(record.encode(), AES.block_size)
    encrypted_record = cipher.encrypt(padded_record)

    # create hashes of the original and encrypted files
    original_hash = SHA256.new(record.encode()).hexdigest()
    encrypted_hash = SHA256.new(encrypted_record).hexdigest()

    # sign the encrypted file using elgamal
    r, s = create_signature(encrypted_record)

    uploaded_file.clear()
    uploaded_file.append({
        "encrypted_record": encrypted_record,
        "original_hash": original_hash,
        "encrypted_hash": encrypted_hash,
        "r": r,
        "s": s
    })

    print("\nmedical file encrypted and uploaded")
    print("encrypted file:", encrypted_record.hex())
    print("sha-256 hash  :", encrypted_hash)
    print("signature     :", (r, s))


def doctor_menu():
    if len(uploaded_file) == 0:
        print("no file uploaded")
        return

    data = uploaded_file[0]

    # decrypt the complete file using aes
    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(data["encrypted_record"])
    decrypted_record = unpad(decrypted_padded, AES.block_size).decode()

    # check the hash of the decrypted file
    new_hash = SHA256.new(decrypted_record.encode()).hexdigest()
    print("hash valid     :", new_hash == data["original_hash"])

    # verify the elgamal signature
    valid = verify_signature(
        data["encrypted_record"], data["r"], data["s"]
    )
    print("signature valid:", valid)
    print("\ndecrypted medical file:\n")
    print(decrypted_record)


def admin_menu():
    if len(uploaded_file) == 0:
        print("no file uploaded")
        return

    data = uploaded_file[0]
    print("sha-256 hash   :", data["encrypted_hash"])
    print("signature valid:", verify_signature(
        data["encrypted_record"], data["r"], data["s"]
    ))


while True:
    print("\n========== medsecure ==========")
    print("1. patient")
    print("2. doctor")
    print("3. admin")
    print("4. exit")

    choice = input("choose role: ")

    if choice == "1":
        patient_menu()
    elif choice == "2":
        doctor_menu()
    elif choice == "3":
        admin_menu()
    elif choice == "4":
        break
    else:
        print("invalid choice")
