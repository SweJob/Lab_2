"""
Key Generator Script:
Generates and manages cryptographic keys for symmetric, asymmetric, and password-based encryption.

Usage:
    keygenerator.py [sym|asym] [filename to store key in]
        sym: Generate a symmetric (Fernet) key. Adds '.key' to filename.
        asym: Generate an asymmetric (RSA) key pair. Adds '.pem' and '.pub' to filename.

Exit codes:
0 - Success
1 - Invalid key type
2 - File error

Author: SweJob
"""

import os
import sys
import argparse
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet


def write_key_file(filename: str, key_data: bytes):
    """Writes key data to a file with error handling.

    Args:
        filename (str): The name of the file to write the key data.
        key_data (bytes): The key data to write to the file.

    Raises:
        FileExistsError: If the file already exists.
        ValueError: If the filename is invalid.
        PermissionError: If there are insufficient permissions to write to the file location.
    """
    # Check if the filename is valid
    if not os.path.basename(filename):
        raise ValueError("Invalid filename. Please provide a valid filename.")

    # Check if the file already exists
    if os.path.exists(filename):
        raise FileExistsError(f"The file '{filename}' already exists. Choose a different name.")

    # Check write permissions for the directory
    directory = os.path.dirname(filename)
    if directory and not os.access(directory, os.W_OK):
        raise PermissionError(f"Insufficient permissions to write to the directory: {directory}")

    # Write the key data to the specified file
    with open(filename, 'wb') as key_file:
        key_file.write(key_data)

def add_to_gitignore(filename: str):
    """Adds the specified filename to the .gitignore file to prevent it from being tracked by Git.

    Args:
        filename (str): The name of the file to add to .gitignore.

    If the .gitignore file does not exist, it will be created. If it does exist, the function
    will append the filename to the file only if it is not already listed to avoid duplicates.
    """
    gitignore_filename = '.gitignore'
    # Use 'with' for file operations
    if not os.path.exists(gitignore_filename):
        with open(gitignore_filename, 'w', encoding='utf-8') as gitignore_file:
            gitignore_file.write(f"{filename}\n")
    else:
        with open(gitignore_filename, 'a', encoding='utf-8') as gitignore_file:
            # Read all lines in a 'with' block
            with open(gitignore_filename, 'r', encoding='utf-8') as existing_file:
                if filename not in existing_file.read():
                    gitignore_file.write(f"{filename}\n")

def generate_symmetric_key() -> bytes:
    """Generates a new symmetric key using the Fernet encryption method.

    Returns:
        bytes: The generated symmetric key.
    """
    key = Fernet.generate_key()
    print("Symmetric key has been generated.")
    return key

def generate_asymmetric_key() -> tuple:
    """Generates an asymmetric RSA key pair and returns them.

    Returns:
        tuple: A tuple containing the private key and public key as bytes.
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    print("Asymmetric keys have been generated.")
    return private_key, public_key

def get_arguments() -> tuple:
    """Parses command-line arguments for key generation.

    Returns:
        tuple: A tuple containing the key type and filename.
    """
    parser = argparse.ArgumentParser(description="Generate cryptographic keys.")
    parser.add_argument('key_type', choices=['sym', 'asym'],
                        help="Specify the key type: 'sym' for symmetric or 'asym' for asymmetric.")
    parser.add_argument('filename', help="Specify the filename to store the key.")
    args = parser.parse_args()
    return args.key_type, args.filename

def main():
    """Main function to execute the key generation."""
    key_type, filename = get_arguments()

    try:
        if key_type == 'sym':
            key = generate_symmetric_key()
            symmetric_key_file = f"{filename}.key"
            write_key_file(symmetric_key_file, key)
            add_to_gitignore(symmetric_key_file)
            sys.exit(0)
        elif key_type == 'asym':
            private_key, public_key = generate_asymmetric_key()
            private_key_file = f"{filename}.pem"  # e.g., mykey.pem
            public_key_file = f"{filename}.pub"    # e.g., mykey.pub

            write_key_file(private_key_file, private_key)
            write_key_file(public_key_file, public_key)
            add_to_gitignore(private_key_file)
            add_to_gitignore(public_key_file)
            sys.exit(0)
        else:
            print("Invalid key type.")
            sys.exit(1)

    except (FileExistsError, ValueError, PermissionError) as e:
        print(f"Error: {e}")
        sys.exit(1)  # Use a specific exit code for these errors

    except OSError as e:
        print(f"File operation error: {e}")
        sys.exit(1)  # Exit for general file-related errors

    # Catch any other unforeseen errors without using a broad Exception
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
