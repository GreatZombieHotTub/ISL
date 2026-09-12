#SAME AS Q3 LAB EXCERCISE
#ElGamal
from random import randint

p = 7919
g = 2
x = 2999

# Public key
h = pow(g, x, p)

message = "Asymmetric Algorithms"

print("Public Key:", (p, g, h))
print("Private Key:", x)

ciphertext = []

# Encryption
for char in message:
    m = ord(char)

    k = randint(1, p - 2)

    c1 = pow(g, k, p)
    s = pow(h, k, p)

    c2 = (m * s) % p

    ciphertext.append((c1, c2))

print("\nOriginal Message:", message)
print("Ciphertext:", ciphertext)

# Decryption
decrypted = ""

for c1, c2 in ciphertext:
    s = pow(c1, x, p)

    s_inverse = pow(s, -1, p)

    m = (c2 * s_inverse) % p

    decrypted += chr(m)

print("Decrypted Message:", decrypted)