def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def find_affine_keys(plain_pair, cipher_pair):
    # Convert letters to numbers (A=0, B=1, ...)
    p1 = ord(plain_pair[0].upper()) - ord('A')
    p2 = ord(plain_pair[1].upper()) - ord('A')
    c1 = ord(cipher_pair[0].upper()) - ord('A')
    c2 = ord(cipher_pair[1].upper()) - ord('A')

    # We have two equations:
    # c1 = (a * p1 + b) mod 26
    # c2 = (a * p2 + b) mod 26
    # Subtracting them eliminates b: (c1 - c2) = a * (p1 - p2) mod 26

    diff_c = (c1 - c2) % 26
    diff_p = (p1 - p2) % 26

    inv_diff_p = mod_inverse(diff_p, 26)
    if inv_diff_p is None:
        raise ValueError("No modular inverse found for plaintext difference.")

    a = (diff_c * inv_diff_p) % 26
    b = (c1 - a * p1) % 26

    return a, b


def affine_decrypt(ciphertext, a, b):
    inv_a = mod_inverse(a, 26)
    if inv_a is None:
        return "Invalid 'a' value."

    plaintext = []
    for char in ciphertext.upper():
        if char.isalpha():
            c_num = ord(char) - ord('A')
            p_num = (inv_a * (c_num - b)) % 26
            plaintext.append(chr(p_num + ord('A')))
        else:
            plaintext.append(char)
    return "".join(plaintext)


def main():
    ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
    known_plain = "ab"
    known_cipher = "GL"

    # Automatically compute keys a and b from the known pair
    a, b = find_affine_keys(known_plain, known_cipher)

    # Decrypt the target ciphertext
    plaintext = affine_decrypt(ciphertext, a, b)

    print("=" * 50)
    print("       AFFINE CIPHER AUTOMATED SOLVER")
    print("=" * 50)
    print(f"Known Plain/Cipher Pair: {known_plain} -> {known_cipher}")
    print(f"Automatically Found Keys: a = {a}, b = {b}")
    print("-" * 50)
    print(f"Ciphertext:   {ciphertext}")
    print(f"Plaintext:    {plaintext}")


if __name__ == "__main__":
    main()