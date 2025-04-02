package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/scrypt"
)

const (
	NonceSize = 12
	TagSize   = 16
)

func aesKeyFromPassword(password string) ([]byte, error) {
	// An 8 bytes is a good length. Keep the salt secret.
	// NOTE: Don't use this salt, generate a new one for you!
	secretSalt := []byte{0x07, 0x2e, 0x12, 0xd7, 0xbc, 0xa3, 0x5b, 0x3a}
	// Use scrypt to derive a key from the password and salt.
	// 32768 iterations, 8 bytes of memory, 1 parallel thread, 32 byte key.
	// The parameters can be adjusted based on your security needs.
	return scrypt.Key([]byte(password), secretSalt, 32768, 8, 1, 32)
}

func aesGcmEncrypt(plaintext []byte, keyString string) ([]byte, error) {
	// Decode the hex key to data
	key, err := hex.DecodeString(keyString)
	if err != nil {
		return nil, err
	}
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt
	encrypted := gcm.Seal(nil, nonce, plaintext, nil)

	// Combine the nonce with the ciphertext data
	return append(nonce, encrypted...), nil
}

func aesGcmDecrypt(ciphertext []byte, keyString string) ([]byte, error) {
	// Decode the hex key to data
	key, err := hex.DecodeString(keyString)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("Invalid data")
	}

	// Extract nonce from the beginning of the combined data
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	// Decrypt
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func main() {
	// Create command line flags
	encrypt := flag.BoolP("encrypt", "e", false, "Encrypt the input file")
	decrypt := flag.BoolP("decrypt", "d", false, "Decrypt the input file")
	key := flag.StringP("key", "k", "", "Key (in hex format) to use for encryption/decryption")
	password := flag.StringP("password", "p", "", "Password to use for encryption/decryption")
	inputFile := flag.StringP("input", "i", "", "Input file to encrypt/decrypt")
	outputFile := flag.StringP("output", "o", "", "Output file to write to")
	bufferSize := flag.IntP("buffer", "b", 0, "Buffer size for stream encryption/decryption (optional)")
	flag.CommandLine.SortFlags = false
	flag.Parse()

	if flag.NFlag() == 0 {
		fmt.Println("A simple AES GCM encryption command-line tool.\nCreated by Carlos E. Torres (github.com/cetorres).")
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(0)
	}

	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Check if the operation is valid
	if (!*encrypt && !*decrypt) || (*encrypt && *decrypt) {
		log.Fatal("Invalid operation. Must be either '--encrypt,-e' or '--decrypt,-d'")
	}

	// Check if either a key or password is provided
	if (*key == "" && *password == "") || (*key != "" && *password != "") {
		log.Fatal("Either a key (in hex format) or a password is required. Not both.")
	}
	if *password != "" && *key == "" {
		// Generate a key from the password
		newKey, err := aesKeyFromPassword(*password)
		if err != nil {
			log.Fatal("Error generating key from password:", err)
		}
		*key = hex.EncodeToString(newKey)
	}
	
	if *inputFile == "" {
		log.Fatal("Input file is required")
	}

	if *outputFile == "" {
		log.Fatal("Output file is required")
	}

	if *bufferSize < 0 {
		log.Fatal("Buffer size cannot be negative")
	}
	
	if *bufferSize > 0 {
		// Perform stream encryption/decryption
		file, err := os.Open(*inputFile)
    if err != nil {
			log.Fatal("Error reading input file:", err)
    }
    defer file.Close()

    reader := bufio.NewReader(file)
		var buffer []byte
		if *encrypt {
			buffer = make([]byte, *bufferSize)
		} else if *decrypt{
			buffer = make([]byte, *bufferSize + NonceSize + TagSize)
		}
		var outputData []byte

    for {
        bytesRead, err := reader.Read(buffer)
        if err == io.EOF {
            break
        }
        if err != nil {
            log.Fatal(err)
        }
				
				var outputDataChunk []byte
				if *encrypt {
					outputDataChunk, err = aesGcmEncrypt(buffer[:bytesRead], *key)
				} else if *decrypt {
					outputDataChunk, err = aesGcmDecrypt(buffer[:bytesRead], *key)
				}
				if err != nil {
					log.Fatal("Error during stream encryption/decryption:", err)
				}

				outputData = append(outputData, outputDataChunk...)
    }

		// Write the output data to the output file
		err = os.WriteFile(*outputFile, outputData, 0644)
		if err != nil {
			log.Fatal("Error writing output file:", err)
		}

		fmt.Println("Operation completed successfully.")

	} else {
		// Read the input file
		inputData, err := os.ReadFile(*inputFile)

		if err != nil {
			log.Fatal("Error reading input file:", err)
		}

		// Encrypt or decrypt the input data
		var outputData []byte
		if *encrypt {
			outputData, err = aesGcmEncrypt(inputData, *key)
		} else if *decrypt {
			outputData, err = aesGcmDecrypt(inputData, *key)
		}
		if err != nil {
			log.Fatal("Error during encryption/decryption:", err)
		}

		// Write the output data to the output file
		err = os.WriteFile(*outputFile, outputData, 0644)
		if err != nil {
			log.Fatal("Error writing output file:", err)
		}

		fmt.Println("Operation completed successfully.")
	}
}
