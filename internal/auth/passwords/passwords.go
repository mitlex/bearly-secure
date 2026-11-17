package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength                  = 128
	argon2idSaltLength         = 16
	argon2idIterations  uint32 = 2
	argon2idMemoryKiB   uint32 = 19 * 1024
	argon2idParallelism uint8  = 1
	argon2idKeyLength   uint32 = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}

	salt := make([]byte, argon2idSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey([]byte(password), salt, argon2idIterations, argon2idMemoryKiB, argon2idParallelism, argon2idKeyLength)

	argon2idHashParts := argon2idHash{
		version:     argon2.Version,
		memoryKiB:   argon2idMemoryKiB,
		iterations:  argon2idIterations,
		parallelism: argon2idParallelism,
		salt:        salt,
		derivedKey:  derivedKey,
	}
	return encodeArgon2idHash(argon2idHashParts), nil
}

// Verify reports whether password (typed at login) matches encodedHash (the user's stored hash from signup).
func Verify(password, encodedHash string) bool {
	// Reject passwords over the limit before doing any hashing work.
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}

	// Legacy path: stored value is a 64-char hex SHA-256 digest from before the Argon2id migration.
	storedDigest, isLegacy := decodeLegacyHash(encodedHash)
	if isLegacy {
		candidateDigest := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateDigest[:], storedDigest) == 1
	}

	// Argon2id path: unpack the stored hash into its recipe (version, params, salt) and stored key.
	stored, isArgon2id := parseArgon2idHash(encodedHash)
	if !isArgon2id || stored.version != argon2.Version {
		return false
	}

	// Re-derive a candidate key from the typed password using the stored salt and parameters.
	candidateKey := argon2.IDKey(
		[]byte(password),
		stored.salt,
		stored.iterations,
		stored.memoryKiB,
		stored.parallelism,
		uint32(len(stored.derivedKey)),
	)

	// Compare the candidate key with the stored key in constant time to prevent remote timing attacks.
	return subtle.ConstantTimeCompare(candidateKey, stored.derivedKey) == 1
}

func NeedsRehash(encodedHash string) bool {
	// Legacy path - rehash into Argon2id
	_, isLegacy := decodeLegacyHash(encodedHash)
	if isLegacy {
		return true
	}

	// Stale Argon2id path - rehash with current Argon2id parameters
	stored, isArgon2id := parseArgon2idHash(encodedHash)
	if isArgon2id {
		if stored.version != argon2.Version ||
			stored.memoryKiB != argon2idMemoryKiB ||
			stored.iterations != argon2idIterations ||
			stored.parallelism != argon2idParallelism ||
			uint32(len(stored.derivedKey)) != argon2idKeyLength {
			return true
		}
	}

	// Either...
	// Malformed hash - don't bother putting it through Hash func to rehash it - save compute
	// Or ...
	// Hash is in line with current Argon2id parameter constants - no rehash required
	return false
}
