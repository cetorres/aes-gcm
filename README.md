# AES-GCM Command-Line Tool

This project provides a command-line tool for encrypting and decrypting files using AES-GCM (Advanced Encryption Standard - Galois/Counter Mode). It supports both key-based and password-based encryption/decryption, as well as streaming for large files.

## Features

- **AES-GCM Encryption/Decryption:** Securely encrypt and decrypt files using the robust AES-GCM algorithm.
- **Key-Based Encryption:** Encrypt/decrypt files using a pre-generated 32-byte (256-bit) key provided in hexadecimal format.
- **Password-Based Encryption:** Derive a secure encryption key from a user-provided password using the scrypt key derivation function.
- **Streaming Support:** Efficiently encrypt/decrypt large files by processing them in chunks, minimizing memory usage.
- **Command-Line Interface:** Easy-to-use command-line interface for all encryption and decryption operations.
- **Error Handling:** Comprehensive error handling to provide informative feedback on any issues encountered.

## Prerequisites

- Go (version 1.23 or higher)

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/cetorres/aes-gcm.git
    cd aes-gcm
    ```

2. **Build the executable:**

    ```bash
    go build -ldflags="-s -w" # these flags help create a smaller binary
    ```

3. (Optional) **Install the executable:** Move the `aes-gcm` to your `/usr/local/bin` folder (or other in your `$PATH`)

    ```bash
    sudo mv aes-gcm /usr/local/bin
    ```

## Usage

### Help

To view the help message and available options:

```bash
./aes-gcm # If it is not in your path
aes-gcm # If it is in your path
```

This will display the following output:

```bash
A simple AES GCM encryption command-line tool.
Created by Carlos E. Torres (github.com/cetorres).
Usage of aes-gcm:
  -b, --buffer int     Buffer size for stream encryption/decryption (optional)
  -d, --decrypt        Decrypt the input file
  -e, --encrypt        Encrypt the input file
  -i, --input string   Input file to encrypt/decrypt
  -k, --key string     Key (in hex format) to use for encryption/decryption
  -o, --output string  Output file to write to
  -p, --password string Password to use for encryption/decryption
```

### Encryption

Key-Based Encryption:

```bash
aes-gcm -e -i input.txt -o output.enc -k YOUR_HEX_KEY
```

Password-Based Encryption:

```bash
aes-gcm -e -i input.txt -o output.enc -p YOUR_PASSWORD
```

- -e or --encrypt: Specifies encryption mode.
- -i or --input: Specifies the input file.
- -o or --output: Specifies the output file.
- -p or --password: Specifies the password to use for key derivation.

Stream Encryption (with Buffer):

```bash
aes-gcm -e -i input.txt -o output.enc -p YOUR_PASSWORD -b 4096
```

- -e or --encrypt: Specifies encryption mode.
- -i or --input: Specifies the input file.
- -o or --output: Specifies the output file.
- -p or --password: Specifies the password.
- -b or --buffer: Specifies the buffer size (e.g., 4096 bytes). This enables stream encryption/decryption.

### Decryption

Key-Based Decryption:

```bash
aes-gcm -d -i output.enc -o decrypted.txt -k YOUR_HEX_KEY
```

- -d or --decrypt: Specifies decryption mode.
- -i or --input: Specifies the input file (e.g., output.enc).
- -o or --output: Specifies the output file (e.g., decrypted.txt).
- -k or --key: Specifies the decryption key in hexadecimal format.

Stream Decryption (with Buffer):

```bash
aes-gcm -d -i output.enc -o decrypted.txt -p YOUR_PASSWORD -b 4096
```

- -d or --decrypt: Specifies decryption mode.
- -i or --input: Specifies the input file.
- -o or --output: Specifies the output file.
- -p or --password: Specifies the password used during encryption.
- -b or --buffer: Specifies the buffer size (e.g., 4096 bytes). This enables stream encryption/decryption.

### Important Notes:

- Key/Password Security: Keep your encryption key or password safe and secure. If you lose them, you will not be able to decrypt your files.
- Hex Key Format: The key must be a 32-byte (256-bit) key in hexadecimal format (64 characters long).
- Password-Derived Key: When using a password, the tool uses scrypt to derive a strong cryptographic key. The salt is hardcoded in the file, which means the same password will always generate the same key.
- Stream Encryption/Decryption: When using the buffer option, the tool will process the input file in chunks of the size provided. If you are decrypting, make sure the buffer size is bigger than 28 bytes, to make sure it reads at least the nonce plus the tag.
- Error Messages: The tool displays descriptive error messages when an issue occurs. Check the output carefully when something goes wrong.

## Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request for any bug fixes, improvements, or new features.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
