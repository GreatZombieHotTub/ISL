from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256


# shared des key used for encryption and decryption
des_key = b"a1b2c3d4"

# details of the two students
student_data = """student id: 101
name: alice
course: cce
semester: 5
cgpa: 8.7

student id: 102
name: bob
course: cce
semester: 5
cgpa: 8.3"""

# create a text file and write both records into it
with open("student_records.txt", "w") as file:
    file.write(student_data)

# generate the student's rsa private and public keys
student_private_key = RSA.generate(2048)
student_public_key = student_private_key.publickey()

# store uploaded files while the program is running
uploaded_records = []


def student_menu():
    # read the complete file containing both student records
    with open("student_records.txt", "r") as file:
        record = file.read()

    # create the des cipher using the shared key
    cipher = DES.new(des_key, DES.MODE_ECB)

    # convert the text to bytes and add padding
    padded_record = pad(record.encode(), DES.block_size)

    # encrypt the complete padded file
    encrypted_record = cipher.encrypt(padded_record)

    # hash the original file for faculty to check after decryption
    original_hash = SHA256.new(record.encode())

    # hash the encrypted file and sign its hash with the private key
    encrypted_hash = SHA256.new(encrypted_record)
    signature = pss.new(student_private_key).sign(encrypted_hash)

    # keep only one uploaded file in this simple program
    uploaded_records.clear()

    # save the encrypted file, hashes, and signature in the list
    uploaded_records.append({
        "encrypted_record": encrypted_record,
        "original_hash": original_hash.hexdigest(),
        "encrypted_hash": encrypted_hash.hexdigest(),
        "signature": signature
    })

    print("\nrecord encrypted and uploaded successfully")
    print("encrypted record:", encrypted_record.hex())
    print("sha-256 hash    :", encrypted_hash.hexdigest())
    print("rsa signature   :", signature.hex())


def faculty_menu():
    if len(uploaded_records) == 0:
        print("no records uploaded")
        return

    # get the single complete uploaded file
    data = uploaded_records[0]

    # decrypt the file using the shared des key
    cipher = DES.new(des_key, DES.MODE_ECB)
    decrypted_padded = cipher.decrypt(data["encrypted_record"])

    # remove padding and convert the decrypted bytes back to text
    decrypted_record = unpad(decrypted_padded, DES.block_size).decode()

    # hash the decrypted file and compare it with the stored hash
    new_hash = SHA256.new(decrypted_record.encode()).hexdigest()

    if new_hash == data["original_hash"]:
        print("hash valid: record was not changed")
    else:
        print("hash invalid: record was changed")

    # verify the rsa signature using the student's public key
    try:
        encrypted_hash = SHA256.new(data["encrypted_record"])
        pss.new(student_public_key).verify(
            encrypted_hash,
            data["signature"]
        )
        print("signature valid: record came from the student")
    except ValueError:
        print("signature invalid")

    print("\ndecrypted student file:\n")
    print(decrypted_record)


def hod_menu():
    if len(uploaded_records) == 0:
        print("no records uploaded")
        return

    # hod sees only the hashes and verifies the signatures
    for i in range(len(uploaded_records)):
        data = uploaded_records[i]
        print("\nupload number  :", i + 1)
        print("sha-256 hash   :", data["encrypted_hash"])

        try:
            encrypted_hash = SHA256.new(data["encrypted_record"])
            pss.new(student_public_key).verify(
                encrypted_hash,
                data["signature"]
            )
            print("signature valid")
        except ValueError:
            print("signature invalid")


while True:
    print("\n========== edusecure ==========")
    print("1. student")
    print("2. faculty")
    print("3. hod")
    print("4. exit")

    role = input("choose role: ")

    if role == "1":
        student_menu()
    elif role == "2":
        faculty_menu()
    elif role == "3":
        hod_menu()
    elif role == "4":
        print("program ended")
        break
    else:
        print("invalid choice")