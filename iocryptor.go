// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package iocrypter

import (
	"crypto/aes"
	"crypto/sha512"
	"errors"

	wa "github.com/wneessen/argon2"
	"golang.org/x/crypto/argon2"
)

const (
	// hmacSize represents the size in bytes of the HMAC output, derived from the
	// underlying SHA-512 hash function.
	hmacSize = sha512.Size

	// hmacKeySize defines the size in bytes of the key used for HMAC operations, ensuring
	// sufficient entropy for security.
	hmacKeySize = 32

	// saltSize defines the size in bytes of the cryptographic salt used for hashing
	// or key derivation operations.
	saltSize = 32

	// aesKeySize defines the size in bytes of the key used for AES encryption, ensuring
	// an adequately secure key length.
	aesKeySize = 32

	// blockSize represents the size in bytes of a single block for the AES encryption
	// algorithm.
	blockSize = aes.BlockSize

	// defaultArgon2Threads defines the default number of threads for the Argon2 key
	// derivation function.
	defaultArgon2Threads = 4

	// defaultArgon2Memory defines the default memory in kibibytes for the Argon2 key
	// derivation function.
	defaultArgon2Memory = 64 * 1024

	// defaultArgon2Time defines the default number of iterations for the Argon2 key
	// derivation function.
	defaultArgon2Time = 3
)

var (
	// hashFunc is assigned to sha512.New, providing a hash.Hash implementation for HMAC and similar
	// cryptographic operations.
	hashFunc = sha512.New

	// chunkSize defines the size of data chunks to be processed, measured in bytes; set to
	// 4 kilobytes (4 * 1024).
	chunkSize = 4 * 1024
)

var (
	// ErrMissingData indicates insufficient data to decrypt, suggesting the ciphertext may be
	// incomplete or corrupted.
	ErrMissingData = errors.New("not enough data to decrypt, ciphertext might be corrupted")

	// ErrFailedAuthentication indicates that authentication has failed due to possible data tampering,
	// corruption, or an incorrect password.
	ErrFailedAuthentication = errors.New("authentication failed, data might have been tampered, corrupted " +
		"or password is incorrect")

	// ErrWriteAfterRead indicates that writing to a hashReadWriter instance is not allowed after a read operation.
	ErrWriteAfterRead = errors.New("writing to hashReadWriter after read is not allowed")
)

// DeriveKeys will use Argon2id to derive a AES-256 and a HMAC key from the
// given password and salt. It will use the given Argon2Settings for the key derivation.
func DeriveKeys(password, salt []byte, settings wa.Settings) ([]byte, []byte) {
	key := argon2.IDKey(password, salt, settings.Time, settings.Memory, settings.Threads, settings.KeyLength)
	return key[:aesKeySize], key[aesKeySize : hmacKeySize+aesKeySize]
}
