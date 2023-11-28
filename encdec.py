# github.com/disketteomelette

import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def derive_key(password, salt):
    # Derive a secure key from the password and salt using PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file, output_file, password):
    # Generate a unique random salt
    salt = os.urandom(16)
    
    # Derive the key from the password and salt
    key = derive_key(password, salt)
    
    # Generate a random Initialization Vector (IV)
    iv = os.urandom(16)

    # Configure the cipher using AES in CFB (Cipher Feedback) mode
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    
    # Get the encryptor object from the cipher
    encryptor = cipher.encryptor()

    # Read the content of the input file
    with open(input_file, 'rb') as file:
        plaintext = file.read()

    # Encrypt the content and finalize the encryption operation
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Write the salt, IV, and encrypted text to the output file
    with open(output_file, 'wb') as file:
        file.write(salt + iv + ciphertext)

def decrypt_file(input_file, output_file, password):
    # Read the content of the encrypted file
    with open(input_file, 'rb') as file:
        data = file.read()

    # Extract the salt, IV, and encrypted text from the file
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    # Derive the key from the password and salt
    key = derive_key(password, salt)

    # Configure the cipher using AES in CFB (Cipher Feedback) mode
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    
    # Get the decryptor object from the cipher
    decryptor = cipher.decryptor()

    # Decrypt the content and finalize the decryption operation
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Write the decrypted text to the output file
    with open(output_file, 'wb') as file:
        file.write(plaintext)

def main():
    # Configure the argument parser
    parser = argparse.ArgumentParser(description='Encrypt or decrypt a file with a symmetric key.')
    parser.add_argument('-e', '--encrypt', action='store_true', help='Encrypt the input file')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Decrypt the input file')
    parser.add_argument('-i', '--input', required=True, help='Input file path')
    parser.add_argument('-o', '--output', required=True, help='Output file path')
    parser.add_argument('-p', '--password', required=True, help='Encryption/decryption password')

    # Parse the command line arguments
    args = parser.parse_args()

    # Perform the corresponding action (encrypt or decrypt)
    if args.encrypt:
        encrypt_file(args.input, args.output, args.password)
        print(f'File encrypted and saved to {args.output}')
    elif args.decrypt:
        decrypt_file(args.input, args.output, args.password)
        print(f'File decrypted and saved to {args.output}')
    else:
        # Show the help if no action is specified
        parser.print_help()

if __name__ == '__main__':
    main()
