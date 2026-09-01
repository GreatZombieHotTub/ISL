def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def affine_decrypt(ciphertext, a, b):
    inv_a = mod_inverse(a, 26)

    if inv_a is None:
        return ""

    plaintext = []

    for char in ciphertext.upper():
        if char.isalpha():
            c_num = ord(char) - ord('A')
            p_num = (inv_a * (c_num - b)) % 26
            plaintext.append(chr(p_num + ord('A')))
        else:
            plaintext.append(char)

    return "".join(plaintext)


def brute_force_affine(ciphertext, known_plain, known_cipher):
    print("=" * 60)
    print("          AFFINE CIPHER BRUTE-FORCE ATTACK")
    print("=" * 60)

    print(f"Known Plain/Cipher Pair: {known_plain} -> {known_cipher}")
    print(f"Ciphertext: {ciphertext}")
    print("-" * 60)

    # Try every possible valid value of a
    # a must be relatively prime to 26
    for a in range(26):

        if mod_inverse(a, 26) is None:
            continue

        # Try every possible value of b
        for b in range(26):

            # Check whether "ab" encrypts to "GL"
            test_cipher = ""

            for char in known_plain.upper():
                p = ord(char) - ord('A')
                c = (a * p + b) % 26
                test_cipher += chr(c + ord('A'))

            # If the key satisfies the known plaintext pair
            if test_cipher == known_cipher.upper():

                plaintext = affine_decrypt(ciphertext, a, b)

                print(f"Found Key: a = {a}, b = {b}")
                print(f"Plaintext: {plaintext}")


def main():
    ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

    known_plain = "ab"
    known_cipher = "GL"

    brute_force_affine(
        ciphertext,
        known_plain,
        known_cipher
    )


if __name__ == "__main__":
    main()
