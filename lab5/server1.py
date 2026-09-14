import socket


def hash_function(message):
    hash_value = 5381

    for char in message:
        hash_value = hash_value * 33 + ord(char)
        hash_value = hash_value ^ (hash_value >> 16)
        hash_value = hash_value & 0xFFFFFFFF

    return hash_value


server = socket.socket()
server.bind(("localhost", 9999))
server.listen(1)

print("Server is waiting for connection...")

conn, address = server.accept()

print("Connected to:", address)

data = conn.recv(1024).decode()

print("Received message:", data)

hash_value = hash_function(data)

print("Calculated hash:", hash_value)

conn.send(str(hash_value).encode())

conn.close()
server.close()