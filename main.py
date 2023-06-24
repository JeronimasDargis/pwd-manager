#!/usr/bin/env/ python
from Crypto.Cipher import AES
import optparse
import json
# from Crypto.Random import get_random_bytes
import os


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
    # if options.encryption_mode == "write" and not options.encryption_key:
    #     parser.error("[-] Please specify a key that will be used to encrypt your password, use --help for more info.")
    # if options.encryption_mode == "write" and not options.password:
    #     parser.error("[-] Please specify a password that will be encrypted, use --help for more info.")
    return options


def write_new_password():
    key = input("Enter the AES key (16, 24, or 32 bytes): ")
    text = input("Enter the text to encrypt: ")


    filename = "encrypted_text.json"
    if not os.path.exists(filename):
        with open(filename, 'w') as file:
            pass

    append_encrypted_text(filename, key, text)
    print("Text encrypted and appended to", filename)


def read_password():
    print("read password")


def encrypt_text(key, text):

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return cipher.nonce + tag + ciphertext


# def append_encrypted_text(filename, key, text):
#     encrypted_text = encrypt_text(key, text)
#     with open(filename, 'ab') as file:
#         file.write(encrypted_text)
#         file.write(b'\n')


def append_encrypted_text(filename, key, text):
    encrypted_text = encrypt_text(key, text)
    print(encrypted_text)

    # Load existing data from the file, if any
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
    except (IOError, ValueError):
        data = {}

    # Update the data with the new encrypted text
    data["secret_key"] = encrypted_text

    # Save the updated data to the file
    with open(filename, 'w') as file:
        json.dump(data, file)

    print("Text encrypted and saved to", filename)


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





