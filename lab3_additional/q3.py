#THIS IS WRONG FIX IT
#RSA
#just use the og one in the Q1 LAB EXERCISE
n = 323
e = 5
d = 173

message = "Cryptographic Protocols"

# Encryption
ciphertext = []

for char in message:
    m = ord(char)

    c = pow(m, e, n)

    ciphertext.append(c)

print("Original Message:", message)
print("Ciphertext:", ciphertext)


# Decryption
decrypted = ""

for c in ciphertext:
    m = pow(c, d, n)

    decrypted += chr(m)

print("Decrypted Message:", decrypted)