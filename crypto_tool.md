# User Guide for Encryption/Decryption Tool (crypto_tool.py)

### Overview
The crypto_tool.py script enables encryption and decryption of files using symmetric, asymmetric, or password-based keys.  
It supports command-line interface usage and can also be imported as a module.

### Usage
python crypto_tool.py -e/-d [keytype] [keyfile/password] [input_files...]
Parameters
- -e: Encrypt files.
- -d: Decrypt files.
- keytype: Specify the key type:
   - sym: Symmetric encryption (requires a .key file).
   - asym: Asymmetric encryption (requires a public key .pub file).
   - pwd: Password-based encryption (requires a password).
- keyfile/password: The key file or password for the selected key type.
- input_files: One or more filenames to process (wildcards allowed, e.g., *.txt).

### Examples
1. Encrypt a File with Symmetric Key:  
   python crypto_tool.py -e sym my_symmetric_key.key myfile.txt  
   This command encrypts myfile.txt using the symmetric key stored in my_symmetric_key.key.
2. Decrypt a File with Symmetric Key:  
   python crypto_tool.py -d sym my_symmetric_key.key myfile.txt.sym.enc  
   This command decrypts myfile.txt.sym.enc using the symmetric key stored in my_symmetric_key.key.
3. Encrypt a File with Asymmetric Public Key:  
   python crypto_tool.py -e asym my_asymmetric_key.pub myfile.txt  
   This command encrypts myfile.txt using the public key stored in my_asymmetric_key.pub.
4. Decrypt a File with Asymmetric Private Key:  
   python crypto_tool.py -d asym my_asymmetric_key.pem myfile.txt.asym.enc  
   This command decrypts myfile.txt.asym.enc using the private key stored in my_asymmetric_key.pem.
5. Encrypt a File with Password:  
   python crypto_tool.py -e pwd mypassword myfile.txt  
   This command encrypts myfile.txt using mypassword.
6. Decrypt a File with Password:  
   python crypto_tool.py -d pwd mypassword myfile.txt.pwd.enc  
   This command decrypts myfile.txt.pwd.enc using mypassword.
   
### Notes  
Ensure that the necessary libraries (e.g., pycryptodome, cryptography) are installed before running the script.  
For Windows users, it may be necessary to use python instead of python3, depending on your environment.
