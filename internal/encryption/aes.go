package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

var (
	appKey           = os.Getenv("APP_AES_KEY")
	defaultAesCipher *AESCipher
)

func init() {
	defaultAesCipher = MustNewAESCipher(MustLoadBase64AesKey(appKey))
}

type AESCipher struct {
	cipher cipher.AEAD
}

func DefaultAesCipher() *AESCipher {
	return defaultAesCipher
}

func MustLoadBase64AesKey(base64Key string) []byte {
	key, err := LoadBase64AesKey(base64Key)
	if err != nil {
		panic(err)
	}
	return key
}

func LoadBase64AesKey(base64Key string) ([]byte, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 key: %w", err)
	}
	l := len(keyBytes)
	// Validate key length for AES
	if l == 16 || l == 24 || l == 32 {
		return keyBytes, nil
	}
	return nil, fmt.Errorf("invalid key length: %d (must be 16, 24, or 32 bytes)", len(keyBytes))
}

func MustNewAESCipher(key []byte) *AESCipher {
	c, err := NewAESCipher(key)
	if err != nil {
		panic(err)
	}
	return c
}

// NewCipher creates an cipher.AEAD from a 32-byte key (AES-256)
func NewAESCipher(key []byte) (*AESCipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256-GCM")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AESCipher{cipher: gcm}, nil
}

// Encrypt encrypts a plaintext and returns base64-encoded ciphertext
func (e *AESCipher) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, e.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := e.cipher.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decodes and decrypts a base64 ciphertext back to plaintext
func (e *AESCipher) Decrypt(ciphertextBase64 string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}
	nonceSize := e.cipher.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := e.cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
