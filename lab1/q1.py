# Helper function to find the modular multiplicative inverse
def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    raise ValueError(f"Modular inverse for {a} does not exist.")


def q1_menu():
    text = "I am learning information security"

    while True:
        print("=" * 40)
        print("       LAB 1: EXERCISE 1 MENU")
        print("=" * 40)
        print(f"Original Message: \"{text}\"\n")
        print("1. Additive Cipher (key = 20)")
        print("2. Multiplicative Cipher (key = 15)")
        print("3. Affine Cipher (key = 15, 20)")
        print("4. Exit")
        print("-" * 40)

        choice = input("Enter your choice (1-4): ").strip()
        print()

        # Remove spaces and convert to lowercase using your method
        clean_text = text.replace(" ", "").lower()

        if choice == '1':
            # --- Additive Cipher (Your original logic) ---
            additive_result = ""
            for char in clean_text:
                num = ord(char) - ord('a')
                new_num = (num + 20) % 26
                additive_result += chr(new_num + ord('a'))

            # Decrypt Additive
            additive_decrypt = ""
            for char in additive_result:
                num = ord(char) - ord('a')
                orig_num = (num - 20) % 26
                additive_decrypt += chr(orig_num + ord('a'))

            print("Ciphertext:", additive_result)
            print("Decrypted: ", additive_decrypt)

        elif choice == '2':
            # --- Multiplicative Cipher ---
            key = 15
            inv_key = mod_inverse(key, 26)

            mult_result = ""
            for char in clean_text:
                num = ord(char) - ord('a')
                new_num = (num * key) % 26
                mult_result += chr(new_num + ord('a'))

            mult_decrypt = ""
            for char in mult_result:
                num = ord(char) - ord('a')
                orig_num = (num * inv_key) % 26
                mult_decrypt += chr(orig_num + ord('a'))

            print("Ciphertext:", mult_result)
            print("Decrypted: ", mult_decrypt)

        elif choice == '3':
            # --- Affine Cipher ---
            key_a, key_b = 15, 20
            inv_a = mod_inverse(key_a, 26)

            affine_result = ""
            for char in clean_text:
                num = ord(char) - ord('a')
                new_num = ((num * key_a) + key_b) % 26
                affine_result += chr(new_num + ord('a'))

            affine_decrypt = ""
            for char in affine_result:
                num = ord(char) - ord('a')
                orig_num = (inv_a * (num - key_b)) % 26
                affine_decrypt += chr(orig_num + ord('a'))

            print("Ciphertext:", affine_result)
            print("Decrypted: ", affine_decrypt)

        elif choice == '4':
            print("Exiting lab program.")
            break
        else:
            print("Invalid choice! Enter 1-4.")

        print("\n" + "=" * 40 + "\n")


if __name__ == "__main__":
    q1_menu()