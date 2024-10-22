# User Guide for ShellCode obfuscator (sc_obfuscator.py)

### Overview
The sc_obfuscator.py script takes the provided bytes and obfuscates them and returns the result as a hexadecimal string.
To obfuscate and deabfuscate you need the password and the number of bitrotations to do


### Usage
`python sc_obfusactor.py [-o|-d] [passphrase] [bits to rotate][shellcode|hexstring]

**Key Types ** 
  - -o: obfuscate input bytes, return a comma separated hexstring
  - -d: deobfuscate a comma separeted hexstring, return bytes
  - passphrase: phrase to xor the data against
  - bits: Number of bits to rotate each byte
  - shellcode-bytes: the shellcode as file of bytes that should be obfuscated
  - hexstring: the hexstring as file of hexstrings that should be deobfuscated

### Examples
1. **Obfuscate File:**
    `python sc_obfuscator.py -o "my_secret_passphrase" 3 "shellcode.bin"`
    Output: shellcode.bin.hex (obfuscated file)
   
2. **Deobfuscate File:**
    `python sc_obfuscator.py -d "my_secret_passphrase" 3 "shellcode.bin.hex"`
    Output: shellcode.bin (deobfuscated file)
   
### Notes
For Windows users, it may be necessary to use python instead of python3, depending on your environment.