# User Guide for Key Generator Tool (keygenerator.py)

### Overview
The keygenerator.py script generates cryptographic keys for symmetric and asymmetric encryption.  
Users can generate keys and save them to files for later use in encryption and decryption operations.

### Usage
`python keygenerator.py [sym|asym] [filename to store key in]`

**Key Types ** 
- sym: Generate a symmetric key  
(stored with a .key extension).
- asym: Generate an asymmetric key pair   
(private key stored with a .pem extension, public key stored with a .pub extension).

### Examples
1. **Generate a Symmetric Key:**  
   `python keygenerator.py sym my_symmetric`
   This command creates a symmetric key  
   Saves it to my_symmetric_key.key.
   
2. **Generate an Asymmetric Key Pair:**  
   `python keygenerator.py asym my_asymmetric`
   This command creates an asymmetric key pair.  
   Saves private key as my_asymmetric_key.pem  
   Saves public key as my_asymmetric_key.pub.
   
### Notes
Ensure that the necessary libraries (e.g., pycryptodome, cryptography) are installed before running the script.  
For Windows users, it may be necessary to use python instead of python3, depending on your environment.