"""
Shift Cipher:
Encryption → C = (P + K) mod 26
Decryption → P = (C - K) mod 26
Key recovery → K = (C - P) mod 26
"""

def decrypt_shift(ciphertext, shift):
    plaintext = ""
    for char in ciphertext.upper():
        if char.isalpha():
            # Shift backward by the key value
            original_num = (ord(char) - ord("A") - shift) % 26
            plaintext += chr(original_num + ord("A"))
        else:
            plaintext += char
    return plaintext


def find_shift_and_decrypt(known_plain, known_cipher, target_cipher):
    # Find the shift key using the first letter of the known pair
    # Cipher = (Plain + shift) % 26  ==>  shift = (Cipher - Plain) % 26
    p_num = ord(known_plain[0].upper()) - ord("A")
    c_num = ord(known_cipher[0].upper()) - ord("A")
    shift = (c_num - p_num) % 26

    """
So we can calculate the shift:

$$ K = (C-P)\mod26 $$

Using the first letters:

Y = 24
C = 2
K=(2−24)mod26=4
So the shift key = 4.

Then decrypt XVIEWYWI by shifting every letter back by 4:"""

    # Decrypt the target ciphertext
    plaintext = decrypt_shift(target_cipher, shift)

    return shift, plaintext


def main():
    known_plain = "yes"
    known_cipher = "CIW"
    target_cipher = "XVIEWYWI"

    shift, decrypted_text = find_shift_and_decrypt(
        known_plain, known_cipher, target_cipher
    )

    print("=" * 50)
    print("           SHIFT CIPHER ATTACK SOLVER")
    print("=" * 50)
    print(f"Known Plaintext:  {known_plain}")
    print(f"Known Ciphertext: {known_cipher}")
    print(f"Derived Shift:    {shift}")
    print("-" * 50)
    print(f"Target Ciphertext: {target_cipher}")
    print(f"Decrypted Plaintext: {decrypted_text}")


if __name__ == "__main__":
    main()
