import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256


host = "127.0.0.1"
port = 5000

# aes-256 key shared by the student and faculty
aes_key = b"0123456789abcdef0123456789abcdef"

# two academic records
student_data = """student id: 101
name: alice
cgpa: 8.7

student id: 102
name: bob
cgpa: 8.3"""

# create the academic record file
with open("student_records.txt", "w") as file:
    file.write(student_data)


def send_data(connection, data):
    # send the size first and then send the actual data
    connection.sendall(len(data).to_bytes(4, "big"))
    connection.sendall(data)


def receive_exact(connection, size):
    # keep receiving until the required number of bytes arrives
    data = b""

    while len(data) < size:
        part = connection.recv(size - len(data))

        if not part:
            raise ConnectionError("connection closed")

        data += part

    return data


def receive_data(connection):
    # receive the size and then receive that much data
    size_data = receive_exact(connection, 4)
    size = int.from_bytes(size_data, "big")
    return receive_exact(connection, size)


def student_server():
    # read the complete student record file
    with open("student_records.txt", "r") as file:
        record = file.read()

    # encrypt the complete file using aes
    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded_record = pad(record.encode(), AES.block_size)
    encrypted_record = cipher.encrypt(padded_record)

    # hash the original file for the faculty integrity check
    original_hash = SHA256.new(record.encode()).digest()

    # generate rsa keys and sign the encrypted file's hash
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    encrypted_hash = SHA256.new(encrypted_record)
    signature = pss.new(private_key).sign(encrypted_hash)

    # convert the public key into bytes before sending
    public_data = public_key.export_key()

    # create the server and wait for the faculty client
    server = socket.socket()
    server.bind((host, port))
    server.listen(1)

    print("waiting for faculty...")
    connection, address = server.accept()

    # send all four items to the faculty
    send_data(connection, public_data)
    send_data(connection, encrypted_record)
    send_data(connection, original_hash)
    send_data(connection, signature)

    print("encrypted and signed file sent")

    connection.close()
    server.close()


def faculty_client():
    # connect to the student server
    client = socket.socket()
    client.connect((host, port))

    # receive all four items from the student
    public_data = receive_data(client)
    encrypted_record = receive_data(client)
    original_hash = receive_data(client)
    signature = receive_data(client)

    # rebuild the student's rsa public key
    public_key = RSA.import_key(public_data)

    # verify the signature before trusting the file
    try:
        encrypted_hash = SHA256.new(encrypted_record)
        pss.new(public_key).verify(encrypted_hash, signature)
        print("signature valid")
    except ValueError:
        print("signature invalid")
        client.close()
        return

    # decrypt the complete file using the shared aes key
    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(encrypted_record)
    decrypted_record = unpad(
        decrypted_padded,
        AES.block_size
    ).decode()

    # hash the decrypted file and compare it with the received hash
    new_hash = SHA256.new(decrypted_record.encode()).digest()
    print("hash valid:", new_hash == original_hash)

    print("\ndecrypted student records:\n")
    print(decrypted_record)

    client.close()


print("1. student server")
print("2. faculty client")

choice = input("choose role: ")

if choice == "1":
    student_server()
elif choice == "2":
    faculty_client()
else:
    print("invalid choice")
