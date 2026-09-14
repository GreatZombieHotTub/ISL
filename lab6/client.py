import socket
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

HOST = "127.0.0.1"
PORT = 5000


def receive_exact(connection, size):

    data = b""

    while len(data) < size:
        part = connection.recv(size - len(data))

        if not part:
            raise ConnectionError("Connection closed")

        data += part

    return data


client = socket.socket()
client.connect((HOST, PORT))

public_size = int.from_bytes(
    receive_exact(client, 4),
    "big"
)

message_size = int.from_bytes(
    receive_exact(client, 4),
    "big"
)

signature_size = int.from_bytes(
    receive_exact(client, 4),
    "big"
)

public_data = receive_exact(client, public_size)
message = receive_exact(client, message_size)
signature = receive_exact(client, signature_size)

public_key = RSA.import_key(public_data)

try:
    message_hash = SHA256.new(message)
    pss.new(public_key).verify(message_hash, signature)

    print("Message:", message.decode())
    print("Signature is valid")

except ValueError:
    print("Signature is invalid")

client.close()