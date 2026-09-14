def hash_function(message):
    hash_value = 5381

    for char in message:
        hash_value = hash_value * 33 + ord(char)
        hash_value = hash_value ^ (hash_value >> 16)
        hash_value = hash_value & 0xFFFFFFFF

    return hash_value


message = input("Enter a message: ")

hash_value = hash_function(message)

print("Message:", message)
print("Hash value:", hash_value)
print("Hash value in hexadecimal:", hex(hash_value))