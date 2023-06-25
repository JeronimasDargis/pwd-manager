#!/usr/bin/env/ python

# utils
from utils.helper_functions import transform_key, encrypt_text, decrypt_text

# constants
from constants import KEY_MIN_LENGTH, FILENAME, MODE_WRITE, MODE_READ

# libraries
import optparse
import binascii
import os
import getpass


filename = FILENAME


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-m", "--mode", dest="encryption_mode", help="Mode of the encryption. Possible values are "
                                                                   "'write' or 'read'.")
    (options, arguments) = parser.parse_args()
    if not options.encryption_mode:
        parser.error("[-] Please specify a mode, use --help for more info.")
    return options


# function that takes a string "password" and appends to the encrypted_password.txt file
def write_new_password():
    key = getpass.getpass("Enter your MASTER password (must be min 12 characters): ")

    if not len(key) >= KEY_MIN_LENGTH:
        print("password must be 12 characters or longer!")
        return

    search_key = raw_input("Enter your password name (will be used to find your password to decrypt):")

    if not search_key:
        print("Please provide name that your password will be stored under!")
        return

    password = raw_input("Enter the password to encrypt: ")

    if not password:
        print("Please provide your password that will be encrypted under the provided name!")
        return

    hashed_key = transform_key(key)

    if not os.path.exists(filename):
        with open(filename, 'w') as file:
            pass

    append_encrypted_text(hashed_key, password, search_key)
    print("Password for " + search_key + " encrypted and appended to your library!")


def read_password():
    key = getpass.getpass("Enter your MASTER password: ")

    if not key:
        print("Please provide your MASTER password")
        return

    search_key = raw_input("Enter the password name to decrypt: ")

    if not search_key:
        print("Please provide name that your password will is stored under!")
        return

    hashed_key = transform_key(key)

    decrypted_value = read_encrypted_text(hashed_key, search_key)
    if decrypted_value is not None:
        print("Password for " + search_key + ": " + decrypted_value)
    else:
        print("Password not found in the file.")


def append_encrypted_text(key, password, search_key):
    encrypted_text = encrypt_text(key, password)

    with open(filename, 'ab') as file:
        file.write(search_key + ":" + binascii.hexlify(encrypted_text) + "\n")


def read_encrypted_text(key, search_key):
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
    if user_input.encryption_mode == MODE_WRITE:
        write_new_password()

    if user_input.encryption_mode == MODE_READ:
        read_password()


if __name__ == '__main__':
    main()





