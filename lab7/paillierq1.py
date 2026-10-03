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
    c = (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)
    return c

def decrypt(private_key, public_key, c):
    lam, mu = private_key
    n, g = public_key
    nsquare = n * n
    x = pow(c, lam, nsquare)
    L = (x - 1) // n
    return (L * mu) % n

def homomorphic_add(c1, c2, public_key):
    n, g = public_key
    return (c1 * c2) % (n * n)

public_key, private_key = generate_keys()

a = 15
b = 25

c1 = encrypt(public_key, a)
c2 = encrypt(public_key, b)

c_sum = homomorphic_add(c1, c2, public_key)
result = decrypt(private_key, public_key, c_sum)

print("Ciphertext of 15:", c1)
print("Ciphertext of 25:", c2)
print("Encrypted sum:", c_sum)
print("Decrypted sum:", result)
print("Expected sum:", a + b)