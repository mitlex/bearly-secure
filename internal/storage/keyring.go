//lint:file-ignore U1000 Some code in this file is used later

package storage

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var keyVersionPattern = regexp.MustCompile(`^[a-z0-9]+(?:_[a-z0-9]+)*$`)

type Keyring struct {
	activeVersion string
	keys          map[string][32]byte
	randomSource  io.Reader
}

type versionedEncryptedPayload struct {
	KeyVersion string
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

type serializedEncryptedPayload struct {
	KeyVersion string `json:"keyVersion"`
	Nonce      string `json:"nonce"`
	AuthTag    string `json:"authTag"`
	Ciphertext string `json:"ciphertext"`
}

func NewKeyring(activeVersion string, keys map[string][32]byte) (*Keyring, error) {
	activeVersion = strings.ToLower(strings.TrimSpace(activeVersion))
	if !keyVersionPattern.MatchString(activeVersion) {
		return nil, fmt.Errorf("invalid encryption key version: %s", activeVersion)
	}
	keyCopies := make(map[string][32]byte, len(keys))
	for version, key := range keys {
		normalizedVersion := strings.ToLower(strings.TrimSpace(version))
		if !keyVersionPattern.MatchString(normalizedVersion) {
			return nil, fmt.Errorf("invalid encryption key version: %s", version)
		}
		if _, exists := keyCopies[normalizedVersion]; exists {
			return nil, fmt.Errorf("duplicate encryption key version: %s", normalizedVersion)
		}
		keyCopies[normalizedVersion] = key
	}
	if _, exists := keyCopies[activeVersion]; !exists {
		return nil, fmt.Errorf("no encryption key configured for active version: %s", activeVersion)
	}
	return &Keyring{activeVersion: activeVersion, keys: keyCopies, randomSource: rand.Reader}, nil
}

func (keyring *Keyring) ActiveVersion() string {
	return keyring.activeVersion
}

func (keyring *Keyring) Encrypt(plaintext []byte) (string, error) {
	// Require a configured keyring
	configuredKeyring, err := requireKeyring(keyring)
	if err != nil {
		return "", err
	}

	// Get active key from keyring; reject missing active key
	key, exists := configuredKeyring.keys[keyring.ActiveVersion()]
	if !exists {
		return "", errors.New("Missing active key on keyring.")
	}

	encryptedPayload, err := Encrypt(plaintext, key)
	if err != nil {
		return "", err
	}

	// Bundle payload information into a single string for database storage
	serializedEncryptedPayload, err := serializeEncryptedPayload(versionedEncryptedPayload{
		KeyVersion: keyring.activeVersion,
		Nonce:      encryptedPayload.Nonce,
		AuthTag:    encryptedPayload.AuthTag,
		Ciphertext: encryptedPayload.Ciphertext,
	})
	if err != nil {
		return "", err
	}

	return serializedEncryptedPayload, nil
}

func (keyring *Keyring) Decrypt(serialized string) ([]byte, error) {
	// Require a configured keyring
	configuredKeyring, err := requireKeyring(keyring)
	if err != nil {
		return []byte{}, err
	}

	deserializedEncryptedPayload, err := deserializeEncryptedPayload(serialized)
	if err != nil {
		return []byte{}, err
	}

	// Get key for key version recorded in payload (not necessarily the keyring's active version);
	// reject if no key is stored under that key version
	key, exists := configuredKeyring.keys[deserializedEncryptedPayload.KeyVersion]
	if !exists {
		return []byte{}, errors.New("Missing appropriate key for this payload on keyring.")
	}

	encryptedPayload := EncryptedPayload{
		Nonce:      deserializedEncryptedPayload.Nonce,
		AuthTag:    deserializedEncryptedPayload.AuthTag,
		Ciphertext: deserializedEncryptedPayload.Ciphertext,
	}
	return Decrypt(encryptedPayload, key)
}

func requireKeyring(keyring *Keyring) (*Keyring, error) {
	if keyring == nil {
		return nil, errors.New("data encryption requires a configured keyring")
	}
	return keyring, nil
}

func serializeEncryptedPayload(payload versionedEncryptedPayload) (string, error) {
	serialized, err := json.Marshal(serializedEncryptedPayload{
		KeyVersion: payload.KeyVersion,
		Nonce:      base64.StdEncoding.EncodeToString(payload.Nonce),
		AuthTag:    base64.StdEncoding.EncodeToString(payload.AuthTag),
		Ciphertext: base64.StdEncoding.EncodeToString(payload.Ciphertext),
	})
	if err != nil {
		return "", fmt.Errorf("serialize encrypted payload: %w", err)
	}
	return string(serialized), nil
}

func deserializeEncryptedPayload(serialized string) (versionedEncryptedPayload, error) {
	var serializedPayload serializedEncryptedPayload
	if err := json.Unmarshal([]byte(serialized), &serializedPayload); err != nil {
		return versionedEncryptedPayload{}, errors.New("invalid serialized encrypted payload")
	}
	keyVersion := strings.ToLower(strings.TrimSpace(serializedPayload.KeyVersion))
	if !keyVersionPattern.MatchString(keyVersion) {
		return versionedEncryptedPayload{}, errors.New("invalid serialized encrypted payload")
	}
	nonce, err := decodeBase64(serializedPayload.Nonce)
	if err != nil || len(nonce) != 12 {
		return versionedEncryptedPayload{}, errors.New("invalid serialized encrypted payload")
	}
	authTag, err := decodeBase64(serializedPayload.AuthTag)
	if err != nil || len(authTag) != 16 {
		return versionedEncryptedPayload{}, errors.New("invalid serialized encrypted payload")
	}
	ciphertext, err := decodeBase64(serializedPayload.Ciphertext)
	if err != nil {
		return versionedEncryptedPayload{}, errors.New("invalid serialized encrypted payload")
	}
	return versionedEncryptedPayload{
		KeyVersion: keyVersion,
		Nonce:      nonce,
		AuthTag:    authTag,
		Ciphertext: ciphertext,
	}, nil
}

func decodeBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid base64")
	}
	return decoded, nil
}
