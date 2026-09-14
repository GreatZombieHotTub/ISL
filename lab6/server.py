#USES RSA 
import socket
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

HOST = "127.0.0.1"
PORT = 5000

# Server keys
private_key = RSA.generate(2048)
public_key = private_key.publickey()

message = b"Document sent by server"

# Sign message
message_hash = SHA256.new(message)
signature = pss.new(private_key).sign(message_hash)

public_data = public_key.export_key()

server = socket.socket()
server.bind((HOST, PORT))
server.listen(1)

print("Waiting for client...")

connection, address = server.accept()

# Send sizes first
connection.sendall(
    len(public_data).to_bytes(4, "big")
)

connection.sendall(
    len(message).to_bytes(4, "big")
)

connection.sendall(
    len(signature).to_bytes(4, "big")
)

# Send actual data
connection.sendall(public_data)
connection.sendall(message)
connection.sendall(signature)

print("Signed document sent")

connection.close()
server.close()

