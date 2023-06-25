import hashlib
from Crypto.Cipher import AES


def transform_key(key_str):
    # Encode the string as bytes using UTF-8 encoding
    key_bytes = key_str.encode('utf-8')

    # Calculate the SHA-256 hash of the key bytes
    sha256_hash = hashlib.sha256(key_bytes)

    # Retrieve the digest (hash value) as bytes
    digest_bytes = sha256_hash.digest()

    # Return the first 32 bytes (256 bits) of the digest
    key = digest_bytes[:32]

    return key


def encrypt_text(key, text):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return cipher.nonce + tag + ciphertext


def decrypt_text(key, ciphertext):
    nonce = ciphertext[:16]
    tag = ciphertext[16:32]
    encrypted_text = ciphertext[32:]

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    decrypted_text = cipher.decrypt_and_verify(encrypted_text, tag)
    return decrypted_text



