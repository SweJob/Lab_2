"""
Crypto Tool Script:
Encrypts or decrypts files using various key types (symmetric, asymmetric, password-based).
The script supports command-line interface usage and can be imported as a module.

Usage:
    crypto_tool.py -d [direction] -k [keytype] [keyfile] {-p [password]} [input_files]
    direction: 'en' for encrypt or 'de' for decrypt
    keytype: 'sym' for symmetric, 'asym' for asymmetric, 'pwd' for password-based
    keyfile: file with en/de-cryption key
    password: Required if keytype is 'pwd'
    input_files: Filenames to process (wildcards allowed, e.g. '*.txt')

Exit codes:
0 - Success
1 - Invalid direction or key type
2 - Password required for type 'pwd'
3 - Invalid filename or file processing error

Author: SweJob
"""

import argparse
import sys
import os
import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet


def get_arguments():
    """
    Parse command-line arguments for the encryption/decryption tool.
    """
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files.")

    # Define encryption and decryption flags
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', action='store_true', help="Encryption mode")
    group.add_argument('-d', action='store_true', help="Decryption mode")

    # Define the key type and keyfile/password argument
    parser.add_argument('key_type', choices=['sym', 'asym', 'pwd'],
                        help="Specify the key type: 'sym', 'asym', or 'pwd'.")
    parser.add_argument('key_input', help="Specify the keyfile or password.")

    # Define input file(s)
    parser.add_argument('input_files', nargs='+', help="List of input files to process.")

    args = parser.parse_args()

    direction = 'en' if args.e else 'de'
    return args.key_type, args.key_input, args.input_files, direction


## File handling
def read_file(filename: str) -> bytes:
    """Reads the content of a file in binary mode."""
    try:
        with open(filename, 'rb') as infile:
            return infile.read()
    except FileNotFoundError:
        print(f"Error: The file {filename} was not found.")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied when trying to read {filename}.")
        sys.exit(1)
    except IsADirectoryError:
        print(f"Error: {filename} is a directory, not a file.")
        sys.exit(1)

def write_file(filename: str, content: bytes):
    """Writes the given content to a file in binary mode."""
    if os.path.exists(filename):
        response = input(f"File {filename} already exists. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print(f"Aborted writing to {filename}.")
            return

    try:
        with open(filename, 'wb') as outfile:
            outfile.write(content)
    except PermissionError:
        print(f"Error: Permission denied when trying to write to {filename}.")
        sys.exit(1)
    except IsADirectoryError:
        print(f"Error: {filename} is a directory, not a file.")
        sys.exit(1)


## Loading keys from file
def load_symmetric_key(filename: str):
    """
    Load a symmetric key from a Base64 encoded file.
    :param filename: Filename containing the symmetric key.
    :return: Symmetric key.
    """
    key_data = read_file(filename)  # Use read_file to load key
    return key_data

def load_asymmetric_key(key_file: str):
    """Load an asymmetric RSA key from a PEM file."""
    key_data = read_file(key_file)  # Use read_file to load key
    try:
        return RSA.import_key(key_data)
    except ValueError as e:
        print(f"Error loading key from {key_file}: {e}")
        sys.exit(1)

## Symmetric methods
def encrypt_file_sym(filename: str, key: bytes):
    """Encrypts the content of a file using a symmetric key."""
    plaintext = read_file(filename)  # Step 1: Read the file
    ciphertext = encrypt_symmetric(plaintext, key)  # Step 2: Encrypt the content
    write_file(filename + '.sym.enc', ciphertext)  # Step 3: Write the encrypted content

def encrypt_symmetric(plaintext: bytes, key: bytes) -> bytes:
    """Encrypts data using the symmetric key."""
    fernet = Fernet(key)  # Create a Fernet instance
    return fernet.encrypt(plaintext)  # Return the encrypted content

def decrypt_file_sym(filename: str, key: bytes):
    """Decrypts the content of a file using a symmetric key."""
    ciphertext = read_file(filename)  # Step 1: Read the encrypted file
    plaintext = decrypt_symmetric(ciphertext, key)  # Step 2: Decrypt the content
    write_file(filename[:-8], plaintext)  # Step 3: Write the decrypted content

def decrypt_symmetric(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypts data using the symmetric key."""
    fernet = Fernet(key)  # Create a Fernet instance
    return fernet.decrypt(ciphertext)  # Return the decrypted content

## Assymetric methods

def encrypt_file_asym(filename: str, public_key):
    """Encrypts the content of a file using an asymmetric public key."""
    plaintext = read_file(filename)  # Step 1: Read the file
    ciphertext = encrypt_asymmetric(plaintext, public_key)  # Step 2: Encrypt the content
    write_file(filename + '.asym.enc', ciphertext)  # Step 3: Write the encrypted content

def encrypt_asymmetric(plaintext: bytes, public_key) -> bytes:
    """Encrypts data using the asymmetric public key."""
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext)  # Return the encrypted content

def decrypt_file_asym(filename: str, private_key):
    """Decrypts the content of a file using an asymmetric private key."""
    ciphertext = read_file(filename)  # Step 1: Read the encrypted file
    plaintext = decrypt_asymmetric(ciphertext, private_key)  # Step 2: Decrypt the content
    write_file(filename[:-9], plaintext)  # Step 3: Write the decrypted content

def decrypt_asymmetric(ciphertext: bytes, private_key) -> bytes:
    """Decrypts data using the asymmetric private key."""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)  # Return the decrypted content

## Password-based methods

def encrypt_file_pwd(filename: str, password: str):
    """Encrypts the content of a file using a password."""
    plaintext = read_file(filename)  # Step 1: Read the file
    ciphertext = encrypt_password(plaintext, password)  # Step 2: Encrypt the content
    write_file(filename + '.pwd.enc', ciphertext)  # Step 3: Write the encrypted content

def encrypt_password(plaintext: bytes, password: str) -> bytes:
    """Encrypts data using a password."""
    salt = get_random_bytes(16)  # Generate a new salt
    key = PBKDF2(password, salt, dkLen=32)  # Derive a key
    fernet = Fernet(base64.urlsafe_b64encode(key))  # Create a Fernet instance
    return salt + fernet.encrypt(plaintext)  # Return salt + encrypted content

def decrypt_file_pwd(filename: str, password: str):
    """Decrypts the content of a file using a password."""
    ciphertext = read_file(filename)  # Step 1: Read the encrypted file
    plaintext = decrypt_password(ciphertext, password)  # Step 2: Decrypt the content
    write_file(filename[:-8], plaintext)  # Step 3: Write the decrypted content

def decrypt_password(ciphertext: bytes, password: str) -> bytes:
    """Decrypts data using a password."""
    salt = ciphertext[:16]  # Extract the salt
    key = PBKDF2(password, salt, dkLen=32)  # Derive the key
    fernet = Fernet(base64.urlsafe_b64encode(key))  # Create a Fernet instance
    return fernet.decrypt(ciphertext[16:])  # Return the decrypted content

## Process Orchestration methods

def process_symmetric_files(input_files, direction, key):
    """Process files using symmetric encryption/decryption."""
    for file in input_files:
        if direction == 'en':
            encrypt_file_sym(file, key)
        else:
            decrypt_file_sym(file, key)

def process_asymmetric_files(input_files, direction, key):
    """Process files using asymmetric encryption/decryption."""
    if direction == 'en':
        for file in input_files:
            encrypt_file_asym(file, key)
    else:
        for file in input_files:
            decrypt_file_asym(file, key)

def process_password_files(input_files, direction, password):
    """Process files using password-based encryption/decryption."""
    for file in input_files:
        if direction == 'en':
            encrypt_file_pwd(file, password)
        else:
            decrypt_file_pwd(file, password)

def process_files(input_files, direction, key_or_password, key_type):
    """Process the list of input files based on the direction and key type."""
    if key_type == 'sym':
        key = load_symmetric_key(key_or_password)
        process_symmetric_files(input_files, direction, key)
    elif key_type == 'asym':
        key = load_asymmetric_key(key_or_password)
        process_asymmetric_files(input_files, direction, key)
    elif key_type == 'pwd':
        password = key_or_password
        process_password_files(input_files, direction, password)


def main():
    """Main function to parse arguments and process files."""
    key_type, key_input, input_files, direction = get_arguments()
    process_files(input_files, direction, key_input, key_type)

if __name__ == "__main__":
    main()
