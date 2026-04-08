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
	SaltSize  = 16
)

func generateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	_, err := io.ReadFull(rand.Reader, salt)
	return salt, err
}

func aesKeyFromPassword(password string, salt []byte) ([]byte, error) {
	// Salt is not a secret — it is stored alongside the ciphertext so that the
	// same password can derive the same key on decryption. Its only job is to
	// be unique per encryption so that a pre-computed table built for
	// one encrypted file is useless against any other file.
	return scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
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
		var outputData []byte
		var keyHex string

		if *password != "" {
			if *encrypt {
				// Generate a fresh random salt and store it at the start of the output.
				salt, err := generateSalt()
				if err != nil {
					log.Fatal("Error generating salt:", err)
				}
				derivedKey, err := aesKeyFromPassword(*password, salt)
				if err != nil {
					log.Fatal("Error deriving key from password:", err)
				}
				keyHex = hex.EncodeToString(derivedKey)
				// Prepend salt so decryption can recover it.
				outputData = append(outputData, salt...)
			} else {
				// Read the salt stored at the beginning of the encrypted file.
				salt := make([]byte, SaltSize)
				if _, err := io.ReadFull(reader, salt); err != nil {
					log.Fatal("Error reading salt from file:", err)
				}
				derivedKey, err := aesKeyFromPassword(*password, salt)
				if err != nil {
					log.Fatal("Error deriving key from password:", err)
				}
				keyHex = hex.EncodeToString(derivedKey)
			}
		} else {
			keyHex = *key
		}

		var buffer []byte
		if *encrypt {
			buffer = make([]byte, *bufferSize)
		} else if *decrypt {
			buffer = make([]byte, *bufferSize+NonceSize+TagSize)
		}

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
				outputDataChunk, err = aesGcmEncrypt(buffer[:bytesRead], keyHex)
			} else if *decrypt {
				outputDataChunk, err = aesGcmDecrypt(buffer[:bytesRead], keyHex)
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

		var outputData []byte

		if *encrypt {
			var keyHex string
			if *password != "" {
				// Generate a fresh random salt and store it at the start of the output.
				salt, err := generateSalt()
				if err != nil {
					log.Fatal("Error generating salt:", err)
				}
				derivedKey, err := aesKeyFromPassword(*password, salt)
				if err != nil {
					log.Fatal("Error deriving key from password:", err)
				}
				keyHex = hex.EncodeToString(derivedKey)
				encrypted, err := aesGcmEncrypt(inputData, keyHex)
				if err != nil {
					log.Fatal("Error during encryption:", err)
				}
				// Output: [salt | nonce | ciphertext+tag]
				outputData = append(salt, encrypted...)
			} else {
				outputData, err = aesGcmEncrypt(inputData, *key)
				if err != nil {
					log.Fatal("Error during encryption:", err)
				}
			}
		} else if *decrypt {
			var keyHex string
			if *password != "" {
				if len(inputData) < SaltSize {
					log.Fatal("Invalid data: file too short to contain a salt")
				}
				// Extract the salt stored at the beginning by the encryptor.
				salt := inputData[:SaltSize]
				derivedKey, err := aesKeyFromPassword(*password, salt)
				if err != nil {
					log.Fatal("Error deriving key from password:", err)
				}
				keyHex = hex.EncodeToString(derivedKey)
				outputData, err = aesGcmDecrypt(inputData[SaltSize:], keyHex)
				if err != nil {
					log.Fatal("Error during decryption:", err)
				}
			} else {
				outputData, err = aesGcmDecrypt(inputData, *key)
				if err != nil {
					log.Fatal("Error during decryption:", err)
				}
			}
		}

		// Write the output data to the output file
		err = os.WriteFile(*outputFile, outputData, 0644)
		if err != nil {
			log.Fatal("Error writing output file:", err)
		}

		fmt.Println("Operation completed successfully.")
	}
}
