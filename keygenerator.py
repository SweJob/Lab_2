"""
Key Generator Script:
Generates symmetric or asymmetric keys for encryption and stores them in files.

Usage:
    python keygenerator.py [sym|asym] [output_keyfile]

    sym: Generate a symmetric (Fernet) key.
    asym: Generate an asymmetric (RSA) key pair.

The script stores keys in the specified output files and provides
appropriate file extensions for different key types.

Author: SweJob
"""

import sys
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet


def generate_symmetric_key() -> bytes:
    """
    Generate a symmetric encryption key (Fernet).

    Returns:
        bytes: The generated symmetric key.
    """
    return Fernet.generate_key()


def save_symmetric_key(key: bytes, filename: str) -> None:
    """
    Save the symmetric key to a file.

    Args:
        key (bytes): The symmetric key to save.
        filename (str): The name of the file to store the key in.

    Returns:
        None

    Raises:
        OSError: If there is an issue writing to the file.
    """
    try:
        with open(filename, 'wb') as key_file:
            key_file.write(key)
    except OSError as e:
        print(f"Error: Could not write to file {filename} - {e}")
        sys.exit(1)


def generate_asymmetric_key_pair() -> RSA.RsaKey:
    """
    Generate an RSA asymmetric key pair.

    Returns:
        RSA.RsaKey: The generated RSA key pair.
    """
    return RSA.generate(2048)


def save_asymmetric_keys(private_key: RSA.RsaKey, filename: str) -> None:
    """
    Save the RSA private and public keys to files.

    Args:
        private_key (RSA.RsaKey): The private key to save.
        filename (str): The base filename for storing the keys. 
                        The private key will be stored in [filename].pem, 
                        and the public key in [filename].pub.

    Returns:
        None

    Raises:
        OSError: If there is an issue writing to the files.
    """
    private_key_file = f"{filename}.pem"
    public_key_file = f"{filename}.pub"

    try:
        # Save the private key
        with open(private_key_file, 'wb') as priv_file:
            priv_file.write(private_key.export_key())
        # Save the public key
        with open(public_key_file, 'wb') as pub_file:
            pub_file.write(private_key.publickey().export_key())
    except OSError as e:
        print(f"Error: Could not write to file {private_key_file} or {public_key_file} - {e}")
        sys.exit(1)


def main() -> None:
    """
    Main function to handle key generation based on user input.

    Usage:
        python keygenerator.py [sym|asym] [output_keyfile]

    Command-line arguments:
        sym: Generate a symmetric key.
        asym: Generate an asymmetric key pair.
        output_keyfile: The filename where the key(s) will be stored.

    Returns:
        None

    Raises:
        ValueError: If an invalid key type is specified.
    """
    if len(sys.argv) != 3:
        print("Usage: python keygenerator.py [sym|asym] [output_keyfile]")
        sys.exit(1)

    key_type = sys.argv[1]
    filename = sys.argv[2]

    if key_type == "sym":
        # Generate and save symmetric key
        key = generate_symmetric_key()
        save_symmetric_key(key, filename)
        print(f"Symmetric key saved to {filename}")
    elif key_type == "asym":
        # Generate and save asymmetric key pair
        private_key = generate_asymmetric_key_pair()
        save_asymmetric_keys(private_key, filename)
        print(f"Private key saved to {filename}.pem")
        print(f"Public key saved to {filename}.pub")
    else:
        print(f"Error: Invalid key type '{key_type}'. Use 'sym' or 'asym'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
