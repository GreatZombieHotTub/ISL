import random
import math

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def lcm(a, b):
    return a * b // gcd(a, b)

def generate_keys():
    p = 17
    q = 19

    n = p * q
    nsquare = n * n
    g = n + 1

    lam = lcm(p - 1, q - 1)
    mu = pow(lam, -1, n)

    return (n, g), (lam, mu)

def encrypt(public_key, m):
    n, g = public_key

    while True:
        r = random.randint(1, n - 1)
        if gcd(r, n) == 1:
            break

    return (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)

def decrypt(private_key, public_key, c):
    lam, mu = private_key
    n, g = public_key
    nsquare = n * n

    x = pow(c, lam, nsquare)
    L = (x - 1) // n

    return (L * mu) % n

def add_encrypted(c1, c2, public_key):
    n, g = public_key
    return (c1 * c2) % (n * n)

public_key, private_key = generate_keys()

party1_data = 20
party2_data = 30

ciphertext1 = encrypt(public_key, party1_data)
ciphertext2 = encrypt(public_key, party2_data)

combined_ciphertext = add_encrypted(
    ciphertext1,
    ciphertext2,
    public_key
)

result = decrypt(
    private_key,
    public_key,
    combined_ciphertext
)

print("Party 1 ciphertext:", ciphertext1)
print("Party 2 ciphertext:", ciphertext2)
print("Combined encrypted data:", combined_ciphertext)
print("Decrypted combined result:", result)