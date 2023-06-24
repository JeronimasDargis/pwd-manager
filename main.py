#!/usr/bin/env/ python
from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
import os


# function that takes a string "password" and appends to the encrypted_password.txt file

def encrypt_text(key, text):
    print(key)
    print(text)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return cipher.nonce + tag + ciphertext


def append_encrypted_text(filename, key, text):
    encrypted_text = encrypt_text(key, text)
    with open(filename, 'ab') as file:
        file.write(encrypted_text)
        file.write(b'\n')


def main():
    key = input("Enter the AES key (16, 24, or 32 bytes): ")
    text = input("Enter the text to encrypt: ")
    # text = str(text)
    filename = "encrypted_text.txt"

    if not os.path.exists(filename):
        with open(filename, 'w') as file:
            pass

    append_encrypted_text(filename, key, text)
    print("Text encrypted and appended to", filename)


if __name__ == '__main__':
    main()





