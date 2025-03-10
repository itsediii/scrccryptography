package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

func encryptAES(text string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(text), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptAES(ciphertext string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, encryptedText := data[:nonceSize], data[nonceSize:]
	text, err := aesGCM.Open(nil, nonce, encryptedText, nil)
	if err != nil {
		return "", err
	}

	return string(text), nil
}

func main() {
	key := []byte("thedocumentationsaysthatineed32b") //32-byte key for AES-256

	text := "This is message will be encrypted with AES."
	fmt.Println("Original:", text)

	encrypted, err := encryptAES(text, key)
	if err != nil {
		fmt.Println("AES Encryption error:", err)
		return
	}
	fmt.Println("Encrypted AES:", encrypted)

	decrypted, err := decryptAES(encrypted, key)
	if err != nil {
		fmt.Println("AES Decryption error:", err)
		return
	}
	fmt.Println("Decrypted AES:", decrypted)

	text2 := []byte("And this one will be encrypted with RSA.")
	fmt.Println("Original:", string(text2))

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.PublicKey

	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &publicKey, text2, nil)
	if err != nil {
		fmt.Println("RSA Encryption error:", err)
		panic(err)
	}
	fmt.Println("RSA Encrypted: ", encryptedBytes)

	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		fmt.Println("RSA Decryption error:", err)
		panic(err)
	}
	fmt.Println("RSA Decrypted: ", string(decryptedBytes))

}
