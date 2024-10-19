"""
Krav:
Nyckelgenerering:
Skapa ett skript (ex: generate_key.py) som genererar en symmetrisk nyckel och sparar den i en fil.

Addition:
Generate assymetric key pair. 
Lägg till funktionalitet för att skapa en lösenordsbaserad nyckel med hjälp av PBKDF2.

do not add keys to git (edit gitignore before saving file)
Do not add private keys to git (make sure any gitignore ignores the file before saving it.)
usage:
    keygenerateor.py -f [filename] -k [keytype] {-p [password]}
    keytype in[sym=symmetric key, assym = assymetric keypair, pwd - password-based key]
    if '-k pwd' -p [password] is required

exitcodes:
0 - all went fine
1 - file already exists or invalid filename
2 - type is not valid
3 - password required for type pwd
"""
import sys
import os
import hashlib
import base64
import argparse
from pathlib import Path
from pathvalidate import ValidationError, validate_filename
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA

def get_arguments():
    """ 
    Returning arguments 
    """
    parser = argparse.ArgumentParser(description="Getting arguments for keygenerator.py by SweJob")
    parser.add_argument(
        "-f", type=str,
        required=True,
        help="Filename to store key in"
        )
    parser.add_argument(
        "-k", type=str,
        required=True,
        help="Type of key ('sym', 'asym', 'pwd') to create"
        )
    parser.add_argument(
        "-p", type=str,
        help="Required if keytype is 'pwd'"
        )

    args = parser.parse_args()

    return args

def file_exists(filename:str):
    """ Making this a separate fucntion if I need to add extra things to it """
    checked_file = Path(filename).is_file()
    return checked_file

def is_valid_filename(filename:str):
    """ Checks if a filename is valid to use """
    try:
        validate_filename(filename)
    except ValidationError:
        return False
    return True

def create_sym_key():
    key = Fernet.generate_key()
    return key

def create_assym_key():
    key = RSA.generate(2048)
    return key

def create_pwd_key(password:str):
    # Generate a random salt
    if salt is None:
        salt = os.urandom(16)  # 16 bytes is a common salt size

    #  Derive the key using PBKDF2
    key = hashlib.pbkdf2_hmac(
        'sha256',                   # Hashing algorithm
        password.encode('utf-8'),   # Convert the password to bytes
        salt,                       # The salt
        100000,                     # Number of iterations
        dklen=32                    # Desired key length in bytes
    )

    # Step 4: Return both salt and key (you can store these securely)
    return salt, key

def write_key(filename:str,key:bytes):
    if is_valid_filename(arguments.f):
        if not file_exists(arguments.f):
            with open(filename, "wb") as key_file:
                key_file.write(key)
        else:
            # If file exists
            print(f"File already exists: {arguments.f}")
            sys.exit(1)
    else:
        print(f"Invalid filename: {arguments.f}")
        sys.exit(1)

def main():
    arguments = get_arguments()
    if arguments.k == "sym":
        # If symetric key
        key = create_sym_key()
        # .gitignore key
        # Write key

    elif arguments.k == "assym":
        # If assymetric key pair
        key = create_assym_key()
        
        # .gitignore private key
        # Write private.key
        

    elif arguments.k == "pwd":
        # If password based
        if not arguments.p:
            # If no password provided
            print ("Password needed if keytype 'pwd' is selected")
            sys.exit(3)
        else:
            key = create_pwd_key(arguments.p)
            salt = key[0]
            pwd_key = key[1]
            print("Salt (Base64):", base64.b64encode(salt).decode())
            print("Derived Key (Base64):", base64.b64encode(pwd_key).decode())
            
        # .gitignore salt and derived key
        # Write salt and derived
            
    else:
        print (f"Invalid argument: {arguments.k}")
        sys.exit(2)

if __name__ == "__main__":
    main()
