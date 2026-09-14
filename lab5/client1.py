import socket


def hash_function(message):
    hash_value = 5381

    for char in message:
        hash_value = hash_value * 33 + ord(char)
        hash_value = hash_value ^ (hash_value >> 16)
        hash_value = hash_value & 0xFFFFFFFF

    return hash_value


client = socket.socket()
client.connect(("localhost", 9999))

message = input("Enter message: ")

local_hash = hash_function(message)

print("Original message:", message)
print("Local hash:", local_hash)

client.send(message.encode())

received_hash = client.recv(1024).decode()

print("Hash received from server:", received_hash)

if str(local_hash) == received_hash:
    print("Integrity verified: No corruption or tampering detected.")
else:
    print("Integrity check failed: Data may be corrupted or tampered.")

client.close()