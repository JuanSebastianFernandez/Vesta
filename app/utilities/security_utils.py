import hashlib

def generate_sha256_hash(source_code: str) -> str:
    """
    Generates a SHA-256 hash for a text string (source code).

    Args:
        source_code (str): The content of the code file.

    Returns:
        str: The 64-character SHA-256 hash in hexadecimal format.
    """
    # 1. Create the hash object using the SHA-256 algorithm
    sha256_hasher = hashlib.sha256()

    # 2. Encode the string to bytes (utf-8 is the standard) and update the hasher
    # Hash functions work with bytes, not plain text.
    sha256_hasher.update(source_code.encode('utf-8'))

    # 3. Get the hash in hexadecimal text format
    return sha256_hasher.hexdigest()

# --- Example of usage ---
if __name__ == "__main__":
    example_code = "def hello():\n    print('Hello, VESTA!')"
    hash_result = generate_sha256_hash(example_code)

    print(f"Source Code:\n{example_code}")
    print(f"\nSHA-256 Hash: {hash_result}")
    print(f"Hash Length: {len(hash_result)} characters")