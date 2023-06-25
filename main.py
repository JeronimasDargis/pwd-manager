#!/usr/bin/env/ python
from Crypto.Cipher import AES
import optparse
import binascii
import hashlib
# from Crypto.Random import get_random_bytes
import os


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


# function that takes a string "password" and appends to the encrypted_password.txt file
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-m", "--mode", dest="encryption_mode", help="Defining the mode of the encryption.")
    parser.add_option("-k", "--key", dest="encryption_key", help="The key that will be used to encrypt/decrypt passwords.")
    parser.add_option("-p", "--pass", dest="password", help="Your password to encrypt.")
    parser.add_option("-n", "--name", dest="password", help="Name, that will be used to find your password.")
    (options, arguments) = parser.parse_args()
    if not options.encryption_mode:
        parser.error("[-] Please specify a mode, use --help for more info.")
    return options


def write_new_password():
    key = input("Enter your MASTER password (must be min 12 characters): ")

    if not len(key) >= 12:
        print("password must be 12 characters or longer!")
        return

    name = input("Enter your password name (will be used to find your password to decrypt):")
    if not name:
        print("Please provide name that your password will be stored under!")
        return

    text = input("Enter the password to encrypt: ")

    hashed_key = transform_key(key)

    filename = "encrypted_text.txt"
    if not os.path.exists(filename):
        with open(filename, 'w') as file:
            pass

    append_encrypted_text(filename, hashed_key, text, name)
    print("Text encrypted and appended to", filename)


def read_password():
    key = input("Enter your MASTER password: ")
    search_key = input("Enter the password name to decrypt: ")
    filename = "encrypted_text.txt"

    hashed_key = transform_key(key)

    decrypted_value = read_encrypted_text(filename, hashed_key, search_key)
    if decrypted_value is not None:
        print("Decrypted value:", decrypted_value)
    else:
        print("Key not found in the file.")


def encrypt_text(key, text):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return cipher.nonce + tag + ciphertext


def append_encrypted_text(filename, key, text, name):
    encrypted_text = encrypt_text(key, text)

    with open(filename, 'ab') as file:
        file.write(name + ":" + binascii.hexlify(encrypted_text) + "\n")


def decrypt_text(key, ciphertext):
    nonce = ciphertext[:16]
    tag = ciphertext[16:32]
    encrypted_text = ciphertext[32:]

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    decrypted_text = cipher.decrypt_and_verify(encrypted_text, tag)
    return decrypted_text


def read_encrypted_text(filename, key, search_key):
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if line.startswith(search_key + ":"):
                encrypted_value = line.split(":")[1]
                ciphertext = binascii.unhexlify(encrypted_value)
                decrypted_value = decrypt_text(key, ciphertext)
                return decrypted_value

    return None


def main():
    user_input = get_arguments()
    if user_input.encryption_mode == "write":
        print('user wants to write password')
        write_new_password()

    if user_input.encryption_mode == "read":
        print('user wants to read a password')
        read_password()


if __name__ == '__main__':
    main()





