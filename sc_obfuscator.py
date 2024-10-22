"""
This module provides functions for obfuscating and deobfuscating shellcode
using bitwise operations and a provided passphrase. It supports reading from 
and writing to files in both binary and hexadecimal formats.
"""
import argparse
import os

def get_arguments() -> argparse.Namespace:
    """Parse command-line arguments and return them.

    Returns:
        argparse.Namespace: The parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Shellcode obfuscator.")
    parser.add_argument("-o", action="store_true", help="Obfuscate the shellcode")
    parser.add_argument("-d", action="store_true", help="Deobfuscate the shellcode")
    parser.add_argument("passphrase", help="Passphrase for obfuscation/deobfuscation")
    parser.add_argument("shift", type=int, help="Number of positions to shift bits")
    parser.add_argument("input_file", help="Input file containing shellcode")
    return parser.parse_args()

def rotate_left(value: int, shift: int) -> int:
    """Rotate the bits of value to the left by shift positions.

    Args:
        value (int): The integer value to rotate.
        shift (int): The number of positions to shift left.

    Returns:
        int: The rotated integer value.
    """
    shift %= 8
    shifted_left = value << shift
    masked_left = shifted_left & 0xFF
    overflow_bits = (value >> (8 - shift)) & ((1 << shift) - 1)
    rotated_value = masked_left | overflow_bits
    return rotated_value

def rotate_right(value: int, shift: int) -> int:
    """Rotate the bits of value to the right by shift positions.

    Args:
        value (int): The integer value to rotate.
        shift (int): The number of positions to shift right.

    Returns:
        int: The rotated integer value.
    """
    shift %= 8
    shifted_right = value >> shift
    overflow_bits = (value << (8 - shift)) & 0xFF
    rotated_value = shifted_right | overflow_bits
    return rotated_value

def obfuscate(shellcode: bytes, passphrase: str, shift: int) -> bytes:
    """Obfuscate shellcode using the given passphrase and shift.

    Args:
        shellcode (bytes): The original shellcode to obfuscate.
        passphrase (str): The passphrase used for obfuscation.
        shift (int): The number of positions to shift bits.

    Returns:
        bytes: The obfuscated shellcode as bytes.
    """
    obfuscated_bytes = bytearray()
    for i, byte in enumerate(shellcode):
        key_byte = ord(passphrase[i % len(passphrase)])
        xored_value = byte ^ key_byte
        rotated_value = rotate_left(xored_value, shift)
        obfuscated_bytes.append(rotated_value)
    return bytes(obfuscated_bytes)

def deobfuscate(obfuscated_shellcode: bytes, passphrase: str, shift: int) -> bytes:
    """Deobfuscate shellcode using the given passphrase and shift.

    Args:
        obfuscated_shellcode (bytes): The obfuscated shellcode to deobfuscate.
        passphrase (str): The passphrase used for deobfuscation.
        shift (int): The number of positions to shift bits.

    Returns:
        bytes: The deobfuscated shellcode as bytes.
    """
    deobfuscated_bytes = bytearray()
    for i, byte in enumerate(obfuscated_shellcode):
        key_byte = ord(passphrase[i % len(passphrase)])
        rotated_value = rotate_right(byte, shift)
        de_xored_value = rotated_value ^ key_byte
        deobfuscated_bytes.append(de_xored_value)
    return bytes(deobfuscated_bytes)

def read_file(file_path: str) -> bytes:
    """Read the contents of a file.

    Args:
        file_path (str): The path to the file to read.

    Returns:
        bytes: The contents of the file as bytes.
    """
    with open(file_path, 'rb') as file:
        return file.read()

def write_file(file_path: str, data: bytes) -> None:
    """Write data to a file in binary format.

    Args:
        file_path (str): The path to the file to write.
        data (bytes): The data to write to the file.
    """
    with open(file_path, 'wb') as file:
        file.write(data)

def read_hex_file(file_path: str) -> bytes:
    """Read hexadecimal values from a file and convert them to bytes.

    Args:
        file_path (str): The path to the file containing hex values.

    Returns:
        bytes: The corresponding bytes from the hex values.
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        # Read the contents and strip any whitespace
        contents = file.read().strip()

    # Split by commas and convert hex values to bytes
    hex_values = contents.split(',')

    # Convert hex strings to bytes
    return bytes(int(value.strip(), 16) for value in hex_values if value.strip())

def write_hex_file(file_path: str, data: bytes) -> None:
    """Write data to a file in hexadecimal format.

    Args:
        file_path (str): The path to the file to write hex data.
        data (bytes): The data to write as hex values.
    """
    with open(file_path, 'w', encoding='utf-8') as file:
        hex_values = ', '.join(f'0x{byte:02x}' for byte in data)
        file.write(hex_values)

def main():
    """Main function to execute the shellcode obfuscator."""
    args = get_arguments()

    # Check if the operation is deobfuscation and if the input file has the correct .hex extension
    if args.d and not args.input_file.endswith('.hex'):
        print("Error: Input file must have a .hex extension for deobfuscation.")
        return

    if args.o:
        # Obfuscation code
        obfuscated_shellcode = obfuscate(read_file(args.input_file), args.passphrase, args.shift)
        write_hex_file(args.input_file + '.hex', obfuscated_shellcode)
        print(f"Obfuscated shellcode written to {args.input_file}.hex")
    elif args.d:
        # Deobfuscation code
        obfuscated_shellcode = read_hex_file(args.input_file)
        deobfuscated_shellcode = deobfuscate(obfuscated_shellcode, args.passphrase, args.shift)
        write_file(os.path.splitext(args.input_file)[0], deobfuscated_shellcode)
        print(f"Deobfuscated shellcode written to {os.path.splitext(args.input_file)[0]}")

if __name__ == "__main__":
    main()
