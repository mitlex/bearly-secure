package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {

	// AES is a "block cipher": it only scrambles fixed-size 16-byte
	// chunks at a time. This sets up that raw algorithm with our key
	// (hence the Go type is literally called cipher.Block).
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}

	// GCM wraps the block cipher so it can handle messages of any
	// length, not just 16 bytes, and also produces an auth tag for
	// tamper detection. "aead" = Authenticated Encryption with
	// Associated Data, matching Go's cipher.AEAD type.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}

	// A nonce is a "number used once." It makes every encryption
	// unique, even with the same key and plaintext, so patterns
	// don't leak across messages. Reusing a nonce with the same key
	// breaks that guarantee, so we generate a fresh random value
	// every time using a cryptographically secure random source.
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}

	// Seal encrypts the plaintext and appends the auth tag to the
	// end, returning both "sealed" together as one slice.
	sealed := aead.Seal(nil, nonce, plaintext, nil)

	// Split the sealed blob back into ciphertext and auth tag so we
	// can store/return them as separate fields.
	tagSize := aead.Overhead()
	cipherText := sealed[:len(sealed)-tagSize]
	authTag := sealed[len(sealed)-tagSize:]

	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    authTag,
		Ciphertext: cipherText,
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	// A real payload always has a 12-byte nonce and 16-byte auth tag.
	// Wrong sizes mean corrupted or malicious input, reject early.
	if len(payload.Nonce) != 12 || len(payload.AuthTag) != 16 {
		return []byte{}, errors.New("Cannot decrypt; payload nonce or authentication tag are incorrect # of bytes. Expect 12 bytes and 16 bytes respectively.")
	}

	// Open expects one combined slice (ciphertext + auth tag), the
	// same shape Seal originally produced. Glue them back together.
	// (We allocate a new slice here instead of appending directly to
	// payload.Ciphertext, so we don't risk mutating it in place.)
	sealed := make([]byte, 0, len(payload.Ciphertext)+len(payload.AuthTag))
	sealed = append(sealed, payload.Ciphertext...)
	sealed = append(sealed, payload.AuthTag...)

	// Rebuild the same block cipher + GCM wrapper used in Encrypt.
	// Nothing is "remembered" between calls, only the key matters,
	// so we reconstruct these fresh here.
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return []byte{}, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}

	// Open recalculates the auth tag from the key, nonce, and
	// ciphertext, then compares it to the tag attached at the end
	// of "sealed". A match means the data is genuine, so it returns
	// the plaintext. A mismatch (wrong key, nonce, or tampered data)
	// returns an error instead of bogus output.
	decryptedPayload, err := aead.Open(nil, payload.Nonce, sealed, nil)
	if err != nil {
		return []byte{}, err
	}

	return decryptedPayload, nil
}
