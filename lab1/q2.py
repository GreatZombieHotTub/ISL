def run_vigenere(clean_text):
    v_key = "dollars"
    expanded_key = (v_key * ((len(clean_text) // len(v_key)) + 1))[:len(clean_text)]

    v_cipher = ""
    for p_char, k_char in zip(clean_text, expanded_key):
        p_num = ord(p_char) - ord('a')
        k_num = ord(k_char) - ord('a')
        v_cipher += chr(((p_num + k_num) % 26) + ord('a'))

    v_decrypted = ""
    for c_char, k_char in zip(v_cipher, expanded_key):
        c_num = ord(c_char) - ord('a')
        k_num = ord(k_char) - ord('a')
        v_decrypted += chr(((c_num - k_num) % 26) + ord('a'))

    print("--- Vigenere Cipher Results ---")
    print("Expanded Key:", expanded_key)
    print("Ciphertext:  ", v_cipher)
    print("Decrypted:   ", v_decrypted)


def run_autokey(clean_text):
    initial_key = 7
    keystream = [initial_key] + [ord(p) - ord('a') for p in clean_text[:-1]]

    a_cipher = ""
    for p_char, k_num in zip(clean_text, keystream):
        p_num = ord(p_char) - ord('a')
        a_cipher += chr(((p_num + k_num) % 26) + ord('a'))

    a_decrypted = ""
    dec_keystream = [initial_key]
    for c_char in a_cipher:
        c_num = ord(c_char) - ord('a')
        k_num = dec_keystream[-1]
        p_num = (c_num - k_num) % 26
        dec_keystream.append(p_num)
        a_decrypted += chr(p_num + ord('a'))

    print("--- Autokey Cipher Results ---")
    print("Initial Key: ", initial_key)
    print("Ciphertext:  ", a_cipher)
    print("Decrypted:   ", a_decrypted)


def q2_menu():
    msg2 = "the house is being sold tonight"
    clean_text = msg2.replace(" ", "").lower()

    while True:
        print("=" * 45)
        print("       LAB 1: QUESTION 2 MENU")
        print("=" * 45)
        print(f"Original Message: \"{msg2}\"")
        print(f"Processed (No spaces): {clean_text}\n")
        print("1. Vigenere Cipher (key: 'dollars')")
        print("2. Autokey Cipher (key = 7)")
        print("3. Exit")
        print("-" * 45)

        choice = input("Enter your choice (1-3): ").strip()
        print()

        if choice == '1':
            run_vigenere(clean_text)
        elif choice == '2':
            run_autokey(clean_text)
        elif choice == '3':
            print("Exiting Question 2.")
            break
        else:
            print("Invalid choice! Enter 1-3.")

        print("\n" + "=" * 45 + "\n")


if __name__ == "__main__":
    q2_menu()