// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package iocrypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	wa "github.com/wneessen/argon2"
)

// ErrPassPhraseEmpty is an error indicating that the provided passphrase is empty and must be non-empty.
var ErrPassPhraseEmpty = errors.New("passphrase must not be empty")

func NewEncrypter(r io.Reader, pass []byte) (io.Reader, error) {
	if len(pass) == 0 {
		return nil, ErrPassPhraseEmpty
	}
	return NewEncrypterWithSettings(r, pass, defaultArgon2Memory, defaultArgon2Time, defaultArgon2Threads)
}

func NewEncrypterWithSettings(r io.Reader, password []byte, memory, time uint32, threads uint8) (io.Reader, error) {
	settings := wa.NewSettings(memory, time, threads, saltSize, aesKeySize+hmacSize)
	settingsSerialized := settings.Serialize()
	salt := make([]byte, settings.SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}
	aesKey, hmacKey := DeriveKeys(password, salt, settings)

	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate random iv: %w", err)
	}

	header := make([]byte, len(settingsSerialized)+len(salt)+len(iv))
	copy(header, settingsSerialized)
	copy(header[len(settingsSerialized):], salt)
	copy(header[len(settingsSerialized)+len(salt):], iv)
	headerReader := bytes.NewReader(header)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES block cipher: %w", err)
	}
	streamReader := &cipher.StreamReader{R: r, S: cipher.NewCTR(block, iv)}

	hasher := hmac.New(hashFunc, hmacKey)
	hmacReadWriter := NewHashReadWriter(hasher)

	return io.MultiReader(io.TeeReader(io.MultiReader(headerReader, streamReader), hmacReadWriter), hmacReadWriter), nil
}
