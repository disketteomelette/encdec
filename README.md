# encdec
A simple implementation of AES algorithm in Cipher Feedback (CFB) mode with PBKDF2-HMAC-SHA256 key derivation function. 

Features:

    Encryption: Securely encrypts the content of a specified input file using a user-provided password.
    Decryption: Decrypts an encrypted file to recover the original content using the same password.

Usage:

    Encrypt a File:

python script.py -e -i input.txt -o encrypted.txt -p password123

Decrypt a File:

    python script.py -d -i encrypted.txt -o decrypted.txt -p password123

Dependencies:

    cryptography library: Utilized for cryptographic operations such as key derivation and encryption.

How It Works:

    The script generates a random salt and derives a secure key from the user-provided password and salt using PBKDF2-HMAC-SHA256.
    For encryption, a random Initialization Vector (IV) is generated, and the content of the input file is encrypted using AES in CFB mode.
    The salt, IV, and encrypted text are written to the output file.
    For decryption, the script reads the salt, IV, and encrypted text from the input file.
    The key is derived from the password and salt, and the content is decrypted using AES in CFB mode.
    The decrypted text is written to the output file.

Command-Line Options:

    -e or --encrypt: Flag to indicate encryption operation.
    -d or --decrypt: Flag to indicate decryption operation.
    -i or --input: Path to the input file.
    -o or --output: Path to the output file.
    -p or --password: User-provided password for encryption/decryption.

Example:

Encrypting a file:

python script.py -e -i sensitive_data.txt -o encrypted_data.txt -p my_secure_password

Decrypting a file:

python script.py -d -i encrypted_data.txt -o decrypted_data.txt -p my_secure_password

Note: Ensure that the cryptography library is installed before running the script (pip install cryptography).

Feel free to use and modify this script for your encryption needs. Contributions and suggestions are welcome!
