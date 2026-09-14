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

part1 = message[:len(message)//3]
part2 = message[len(message)//3:2*len(message)//3]
part3 = message[2*len(message)//3:]

print("Sending part 1:", part1)
client.send(part1.encode())

print("Sending part 2:", part2)
client.send(part2.encode())

print("Sending part 3:", part3)
client.send(part3.encode())

client.send("END".encode())

received_hash = client.recv(1024).decode()

print("Hash received from server:", received_hash)

if str(local_hash) == received_hash:
    print("Integrity verified.")
else:
    print("Integrity check failed.")

client.close()