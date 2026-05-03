package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

type CryptoManager struct {
	masterKey []byte
}

type EncryptedData struct {
	Ciphertext string `json:"ciphertext"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
}

func NewCryptoManager(masterPassword string) (*CryptoManager, error) {
	if len(masterPassword) < 12 {
		return nil, errors.New("мастер-пароль должен быть не менее 12 символов")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := argon2.IDKey(
		[]byte(masterPassword),
		salt,
		1,
		64*1024,
		4,
		32,
	)

	return &CryptoManager{
		masterKey: key,
	}, nil
}

func deriveEncryptionKey(masterPassword, salt []byte) []byte {
	return argon2.IDKey(
		masterPassword,
		salt,
		3,
		128*1024,
		4,
		32,
	)
}

func (cm *CryptoManager) Encrypt(plaintext string) (*EncryptedData, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := deriveEncryptionKey(cm.masterKey, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	return &EncryptedData{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
	}, nil
}

func (cm *CryptoManager) Decrypt(ed *EncryptedData) (string, error) {
	salt, err := base64.StdEncoding.DecodeString(ed.Salt)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ed.Ciphertext)
	if err != nil {
		return "", err
	}

	nonce, err := base64.StdEncoding.DecodeString(ed.Nonce)
	if err != nil {
		return "", err
	}

	key := deriveEncryptionKey(cm.masterKey, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("ошибка расшифровки: неверный мастер-пароль или поврежденные данные")
	}

	return string(plaintext), nil
}

func HashMasterPassword(password string) (string, string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		1,
		64*1024,
		4,
		32,
	)

	return base64.StdEncoding.EncodeToString(hash),
		base64.StdEncoding.EncodeToString(salt),
		nil
}

func VerifyMasterPassword(password, storedHash, storedSalt string) bool {
	salt, err := base64.StdEncoding.DecodeString(storedSalt)
	if err != nil {
		return false
	}

	expectedHash, err := base64.StdEncoding.DecodeString(storedHash)
	if err != nil {
		return false
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		1,
		64*1024,
		4,
		32,
	)

	return sha256.Sum256(hash) == sha256.Sum256(expectedHash)
}
