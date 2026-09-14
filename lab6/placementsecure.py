""" 
question 2: placementsecure

develop a secure placement-record management system called placementsecure.

student encrypts the complete placement-record file using aes-128.
student creates an md5 hash and signs the encrypted file using schnorr.
placement officer decrypts the complete file, checks its hash, and verifies the signature.
hod can only see the hash and verify the signature.
use a menu to select student, placement officer, hod, or exit.

algorithms used:

aes-128 encryption
md5 hashing
schnorr digital signal"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import hashlib
import secrets


# aes-128 key shared by the student and placement officer
aes_key = b"0123456789abcdef"

# create a file containing two placement records
placement_data = """student id: 201
name: arjun
company: infosys
package: 6 lpa

student id: 202
name: neha
company: tcs
package: 7 lpa"""

with open("placement_records.txt", "w") as file:
    file.write(placement_data)


# small schnorr values used only for demonstration
p = 23
q = 11
g = 4
x = secrets.randbelow(q - 1) + 1
y = pow(g, x, p)

# this stores one uploaded file while the program runs
uploaded_file = []


def create_signature(message):
    k = secrets.randbelow(q - 1) + 1
    r = pow(g, k, p)
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, "big")
    e = int.from_bytes(
        SHA256.new(message + r_bytes).digest(), "big"
    ) % q
    s = (k + x * e) % q
    return e, s


def verify_signature(message, e, s):
    y_inverse_e = pow(pow(y, e, p), -1, p)
    r_verify = (pow(g, s, p) * y_inverse_e) % p
    r_bytes = r_verify.to_bytes(
        (r_verify.bit_length() + 7) // 8, "big"
    )
    e_verify = int.from_bytes(
        SHA256.new(message + r_bytes).digest(), "big"
    ) % q
    return e == e_verify


def student_menu():
    # read and encrypt the complete placement file
    with open("placement_records.txt", "r") as file:
        record = file.read()

    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded_record = pad(record.encode(), AES.block_size)
    encrypted_record = cipher.encrypt(padded_record)

    # use md5 to check the file in this lab demonstration
    original_hash = hashlib.md5(record.encode()).hexdigest()
    encrypted_hash = hashlib.md5(encrypted_record).hexdigest()

    # sign the encrypted file using schnorr
    e, s = create_signature(encrypted_record)

    uploaded_file.clear()
    uploaded_file.append({
        "encrypted_record": encrypted_record,
        "original_hash": original_hash,
        "encrypted_hash": encrypted_hash,
        "e": e,
        "s": s
    })

    print("\nplacement file encrypted and uploaded")
    print("encrypted file:", encrypted_record.hex())
    print("md5 hash      :", encrypted_hash)
    print("signature     :", (e, s))


def officer_menu():
    if len(uploaded_file) == 0:
        print("no file uploaded")
        return

    data = uploaded_file[0]

    # decrypt the complete placement file
    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(data["encrypted_record"])
    decrypted_record = unpad(decrypted_padded, AES.block_size).decode()

    # compare the md5 hash after decryption
    new_hash = hashlib.md5(decrypted_record.encode()).hexdigest()
    print("hash valid     :", new_hash == data["original_hash"])

    # verify the schnorr signature
    valid = verify_signature(
        data["encrypted_record"], data["e"], data["s"]
    )
    print("signature valid:", valid)
    print("\ndecrypted placement file:\n")
    print(decrypted_record)


def hod_menu():
    if len(uploaded_file) == 0:
        print("no file uploaded")
        return

    data = uploaded_file[0]
    print("md5 hash       :", data["encrypted_hash"])
    print("signature valid:", verify_signature(
        data["encrypted_record"], data["e"], data["s"]
    ))


while True:
    print("\n======= placementsecure =======")
    print("1. student")
    print("2. placement officer")
    print("3. hod")
    print("4. exit")

    choice = input("choose role: ")

    if choice == "1":
        student_menu()
    elif choice == "2":
        officer_menu()
    elif choice == "3":
        hod_menu()
    elif choice == "4":
        break
    else:
        print("invalid choice")
