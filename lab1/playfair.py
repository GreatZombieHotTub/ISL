def generate_playfair_matrix(keyword):
    # Playfair uses a 5x5 matrix, so I and J are treated as the same letter
    keyword = keyword.upper().replace("J", "I")

    # Remove duplicate letters from the keyword while preserving their order
    seen = set()
    unique_key = ""

    for char in keyword:
        if char not in seen and char.isalpha():
            seen.add(char)
            unique_key += char

    # Alphabet used for Playfair (J is omitted because I/J are combined)
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    # Add the remaining unused letters to complete the 25-letter key
    full_key_string = unique_key

    for char in alphabet:
        if char not in seen:
            seen.add(char)
            full_key_string += char

    # Divide the 25 letters into 5 rows of 5 letters each
    matrix = []

    for i in range(0, 25, 5):
        matrix.append(list(full_key_string[i:i + 5]))

    return matrix


def prepare_plaintext(text):
    # Convert to uppercase and replace J with I
    text = text.upper().replace("J", "I")

    # Remove spaces and any non-alphabetic characters
    clean_text = "".join([c for c in text if c.isalpha()])

    # Playfair encrypts two letters (a digraph) at a time
    digraphs = []
    i = 0

    while i < len(clean_text):
        char1 = clean_text[i]

        if i + 1 < len(clean_text):
            char2 = clean_text[i + 1]

            # If both letters are the same, insert X between them
            # Example: BALLOON -> BA LX LO ON
            if char1 == char2:
                digraphs.append(char1 + "X")
                i += 1

            else:
                # Normal pair of different letters
                digraphs.append(char1 + char2)
                i += 2

        else:
            # If one letter remains at the end, add X as padding
            digraphs.append(char1 + "X")
            i += 1

    return digraphs


def find_position(matrix, char):
    # Search the 5x5 matrix to find the row and column of a letter
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c

    return None


def encrypt_pair(pair, matrix):
    # Find the position of both letters in the matrix
    r1, c1 = find_position(matrix, pair[0])
    r2, c2 = find_position(matrix, pair[1])

    # RULE 1: Same row
    # Replace each letter with the letter immediately to its right
    if r1 == r2:
        return (
            matrix[r1][(c1 + 1) % 5]
            + matrix[r2][(c2 + 1) % 5]
        )

    # RULE 2: Same column
    # Replace each letter with the letter immediately below it
    elif c1 == c2:
        return (
            matrix[(r1 + 1) % 5][c1]
            + matrix[(r2 + 1) % 5][c2]
        )

    # RULE 3: Rectangle rule
    # Keep the same rows but swap the columns
    else:
        return matrix[r1][c2] + matrix[r2][c1]


def playfair_cipher_program():

    print("=" * 50)
    print("       PLAYFAIR CIPHER ENCRYPTION")
    print("=" * 50)

    # Keyword used to construct the Playfair matrix
    keyword = "GUIDANCE"

    # Generate the 5x5 key matrix
    matrix = generate_playfair_matrix(keyword)

    print("Generated 5x5 Key Matrix:")

    # Display the matrix
    for row in matrix:
        print(" ".join(row))

    print("-" * 50)

    # Default message given in the lab
    default_msg = "The key is hidden under the door pad"

    # Allow the user to enter their own message
    # If nothing is entered, use the default message
    user_input = input(
        "Enter message [Press Enter to use default]: "
    ).strip()

    plaintext = user_input if user_input else default_msg

    # Clean the plaintext and divide it into digraphs
    digraphs = prepare_plaintext(plaintext)

    # Encrypt every pair using the Playfair rules
    ciphertext = ""

    for pair in digraphs:
        ciphertext += encrypt_pair(pair, matrix)

    # Display the final results
    print("\n--- Results ---")
    print("Original Message:  ", plaintext)
    print("Prepared Digraphs: ", " ".join(digraphs))
    print("Ciphertext:        ", ciphertext)


# Program starts here
if __name__ == "__main__":
    playfair_cipher_program()
