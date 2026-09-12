# 62-character alphabet
# a-z = 0-25
# A-Z = 26-51
# 0-9 = 52-61

alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


# Helper function to find modular multiplicative inverse
def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    raise ValueError("Modular inverse does not exist.")


# Convert character to number
def char_to_num(char):
    return alphabet.index(char)


# Convert number back to character
def num_to_char(num):
    return alphabet[num]


def main():

    # ---------------------------------------------------------
    # INPUT VALIDATION
    # ---------------------------------------------------------

    while True:
        text = input("Enter the message (a-z, A-Z, 0-9 and spaces allowed): ")

        valid = True

        for char in text:
            if char != " " and char not in alphabet:
                valid = False
                break

        if valid and text != "":
            break

        print("Invalid input!")
        print("Only a-z, A-Z, 0-9 and spaces are allowed.")
        print("Please re-enter.\n")


    # ---------------------------------------------------------
    # AFFINE ENCRYPTION
    # ---------------------------------------------------------

    key_a = 15
    key_b = 20
    modulus = 62

    # Find inverse of a for decryption
    inv_a = mod_inverse(key_a, modulus)

    affine_cipher = ""

    for char in text:

        # Spaces have no value and remain unchanged
        if char == " ":
            affine_cipher += " "
        else:
            p = char_to_num(char)

            # C = (aP + b) mod 62
            c = (p * key_a + key_b) % modulus

            affine_cipher += num_to_char(c)


    print("\n--- Affine Cipher ---")
    print("Key a:", key_a)
    print("Key b:", key_b)
    print("Inverse of a:", inv_a)
    print("Affine Ciphertext:", affine_cipher)


    # ---------------------------------------------------------
    # VIGENERE ENCRYPTION
    # ---------------------------------------------------------

    v_key = "dollars"

    vigenere_cipher = ""
    key_index = 0

    for char in affine_cipher:

        # Spaces remain unchanged
        # and DO NOT consume a key character
        if char == " ":
            vigenere_cipher += " "

        else:
            p = char_to_num(char)

            k_char = v_key[key_index % len(v_key)]
            k = char_to_num(k_char)

            # C = (P + K) mod 62
            c = (p + k) % modulus

            vigenere_cipher += num_to_char(c)

            key_index += 1


    print("\n--- Vigenere Cipher ---")
    print("Key:", v_key)
    print("Ciphertext:", vigenere_cipher)


    # ---------------------------------------------------------
    # VIGENERE DECRYPTION
    # ---------------------------------------------------------

    vigenere_decrypted = ""
    key_index = 0

    for char in vigenere_cipher:

        # Spaces remain unchanged
        # and DO NOT consume a key character
        if char == " ":
            vigenere_decrypted += " "

        else:
            c = char_to_num(char)

            k_char = v_key[key_index % len(v_key)]
            k = char_to_num(k_char)

            # P = (C - K) mod 62
            p = (c - k) % modulus

            vigenere_decrypted += num_to_char(p)

            key_index += 1


    print("\n--- Vigenere Decryption ---")
    print("Decrypted:", vigenere_decrypted)


    # ---------------------------------------------------------
    # AFFINE DECRYPTION
    # ---------------------------------------------------------

    affine_decrypted = ""

    for char in vigenere_decrypted:

        # Spaces remain unchanged
        if char == " ":
            affine_decrypted += " "

        else:
            c = char_to_num(char)

            # P = a^-1(C - b) mod 62
            p = (inv_a * (c - key_b)) % modulus

            affine_decrypted += num_to_char(p)


    print("\n--- Affine Decryption ---")
    print("Final Decrypted Message:", affine_decrypted)


    # ---------------------------------------------------------
    # CROSS CHECK
    # ---------------------------------------------------------

    print("\n--- Cross Check ---")

    if affine_decrypted == text:
        print("SUCCESS: Final decrypted message matches original message.")
    else:
        print("ERROR: Decrypted message does not match original message.")


if __name__ == "__main__":
    main()


