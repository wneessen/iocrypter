// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package iocrypter

import (
	"crypto/aes"
	"crypto/sha512"
	"errors"
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
