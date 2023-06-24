#!/usr/bin/env/ python
from Crypto.Cipher import AES
import optparse
# from Crypto.Random import get_random_bytes
import os


# function that takes a string "password" and appends to the encrypted_password.txt file

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-m", "--mode", dest="encryption_mode", help="Defining the mode of the encryption.")
    parser.add_option("-k", "--key", dest="string_key", help="Passing the key that will be used to encrypt/decrypt passwords")
    parser.add_option("-p", "--pass", dest="password", help="Passing the password for encryption.")

    (options, arguments) = parser.parse_args()
    if not options.encryption_mode:
        parser.error("[-] Please specify a mode, use --help for more info.")
    if options.encryption_mode == "write" and not options.string_key:
        parser.error("[-] Please specify a key that will be used to encrypt your password, use --help for more info.")
    if options.encryption_mode == "write" and not options.password:
        parser.error("[-] Please specify a password that will be encrypted, use --help for more info.")
    return options


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
    user_input = get_arguments()
    if user_input.encryption_mode == "write":
        print('user wants to write password')
    if user_input.encryption_mode == "read":
        print('user wants to read a password')

    # key = input("Enter the AES key (16, 24, or 32 bytes): ")
    # text = input("Enter the text to encrypt: ")
    # text = str(text)
    # filename = "encrypted_text.txt"
    #
    # if not os.path.exists(filename):
    #     with open(filename, 'w') as file:
    #         pass
    #
    # append_encrypted_text(filename, key, text)
    # print("Text encrypted and appended to", filename)


if __name__ == '__main__':
    main()





