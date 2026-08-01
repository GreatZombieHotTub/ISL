def generate_playfair_matrix(keyword):
    # Standard Playfair convention: combine I and J
    keyword = keyword.upper().replace("J", "I")

    # Remove duplicates from the keyword while keeping order
    seen = set()
    unique_key = ""
    for char in keyword:
        if char not in seen and char.isalpha():
            seen.add(char)
            unique_key += char

    # Fill the rest of the 5x5 matrix with remaining alphabet letters
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Note: 'J' is omitted
    full_key_string = unique_key
    for char in alphabet:
        if char not in seen:
            seen.add(char)
            full_key_string += char

    # Build the 5x5 grid
    matrix = []
    for i in range(0, 25, 5):
        matrix.append(list(full_key_string[i:i + 5]))

    return matrix


def prepare_plaintext(text):
    text = text.upper().replace("J", "I")
    # Remove spaces and non-alphabetic characters
    clean_text = "".join([c for c in text if c.isalpha()])

    # Process into digraphs (pairs)
    digraphs = []
    i = 0
    while i < len(clean_text):
        char1 = clean_text[i]
        if i + 1 < len(clean_text):
            char2 = clean_text[i + 1]
            if char1 == char2:
                # If letters match, insert filler 'X'
                digraphs.append(char1 + 'X')
                i += 1
            else:
                digraphs.append(char1 + char2)
                i += 2
        else:
            # If single leftover letter at the end, pad with 'X'
            digraphs.append(char1 + 'X')
            i += 1

    return digraphs


def find_position(matrix, char):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None


def encrypt_pair(pair, matrix):
    r1, c1 = find_position(matrix, pair[0])
    r2, c2 = find_position(matrix, pair[1])

    # Rule 1: Same row
    if r1 == r2:
        return matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]

    # Rule 2: Same column
    elif c1 == c2:
        return matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]

    # Rule 3: Rectangle swap
    else:
        return matrix[r1][c2] + matrix[r2][c1]


def playfair_cipher_program():
    print("=" * 50)
    print("       PLAYFAIR CIPHER ENCRYPTION")
    print("=" * 50)

    # Default key mapping as requested: "GUIDANCE" filling first rows
    keyword = "GUIDANCE"
    matrix = generate_playfair_matrix(keyword)

    print("Generated 5x5 Key Matrix:")
    for row in matrix:
        print(" ".join(row))
    print("-" * 50)

    # Allow user input for message, defaulting to the lab sentence if empty
    default_msg = "The key is hidden under the door pad"
    user_input = input(f"Enter message [Press Enter to use default]: ").strip()

    plaintext = user_input if user_input else default_msg
    digraphs = prepare_plaintext(plaintext)

    # Encrypt each digraph
    ciphertext = ""
    for pair in digraphs:
        ciphertext += encrypt_pair(pair, matrix)

    print("\n--- Results ---")
    print("Original Message:  ", plaintext)
    print("Prepared Digraphs: ", " ".join(digraphs))
    print("Ciphertext:        ", ciphertext)


if __name__ == "__main__":
    playfair_cipher_program()