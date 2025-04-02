package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"
)

const rsaChunkSize = 190 // Max data size for 2048-bit RSA with OAEP (SHA-256)

func encryptAESFile(inputFile, outputFile string, key []byte) error {
	in, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	if _, err := out.Write(nonce); err != nil {
		return err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	buffer := make([]byte, 1024)
	for {
		n, err := in.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		ciphertext := aesGCM.Seal(nil, nonce, buffer[:n], nil)
		if _, err := out.Write(ciphertext); err != nil {
			return err
		}
	}

	return nil
}

func decryptAESFile(inputFile, outputFile string, key []byte) error {
	in, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := aesGCM.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := in.Read(nonce); err != nil {
		return err
	}

	buffer := make([]byte, 1040)
	for {
		n, err := in.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		plaintext, err := aesGCM.Open(nil, nonce, buffer[:n], nil)
		if err != nil {
			return err
		}
		if _, err := out.Write(plaintext); err != nil {
			return err
		}
	}

	return nil
}

func encryptRSAFile(inputFile, outputFile string, publicKey *rsa.PublicKey) error {
	in, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	out, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	for i := 0; i < len(in); i += rsaChunkSize {
		end := i + rsaChunkSize
		if end > len(in) {
			end = len(in)
		}

		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, in[i:end], nil)
		if err != nil {
			return err
		}

		chunkSize := uint16(len(ciphertext))
		binary.Write(out, binary.LittleEndian, chunkSize)
		out.Write(ciphertext)
	}

	return nil
}

func decryptRSAFile(inputFile, outputFile string, privateKey *rsa.PrivateKey) error {
	in, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	for {
		var chunkSize uint16
		err := binary.Read(in, binary.LittleEndian, &chunkSize)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		ciphertext := make([]byte, chunkSize)
		_, err = in.Read(ciphertext)
		if err != nil {
			return err
		}

		plaintext, err := privateKey.Decrypt(nil, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
		if err != nil {
			return err
		}

		out.Write(plaintext)
	}

	return nil
}

func main() {
	key := []byte("thedocumentationsaysthatineed32b") // 32-byte key for AES-256

	inputFile := "input.bin"
	encryptedFile := "aesencrypted.txt"
	decryptedFile := "aesdecrypted.txt"

	start := time.Now()
	if err := encryptAESFile(inputFile, encryptedFile, key); err != nil {
		fmt.Println("AES File Encryption error:", err)
		return
	}
	fmt.Println("AES File Encryption Time:", time.Since(start))

	start = time.Now()
	if err := decryptAESFile(encryptedFile, decryptedFile, key); err != nil {
		fmt.Println("AES File Decryption error:", err)
		return
	}
	fmt.Println("AES File Decryption Time:", time.Since(start))

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKey := &privateKey.PublicKey

	rsaEncryptedFile := "rsaencrypted.txt"
	rsaDecryptedFile := "rsadecrypted.txt"

	start = time.Now()
	if err := encryptRSAFile(inputFile, rsaEncryptedFile, publicKey); err != nil {
		fmt.Println("RSA File Encryption error:", err)
		return
	}
	fmt.Println("RSA File Encryption Time:", time.Since(start))

	start = time.Now()
	if err := decryptRSAFile(rsaEncryptedFile, rsaDecryptedFile, privateKey); err != nil {
		fmt.Println("RSA File Decryption error:", err)
		return
	}
	fmt.Println("RSA File Decryption Time:", time.Since(start))
}
