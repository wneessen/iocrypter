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
	"fmt"
	"io"
)

func NewEncrypter(r io.Reader, pass []byte) (io.Reader, error) {
	settings := NewArgon2Settings()
	return NewEncrypterWithSettings(r, pass, settings)
}

func NewEncrypterWithSettings(r io.Reader, password []byte, settings Argon2Settings) (io.Reader, error) {
	settingsSerialized, err := settings.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Argon2 settings: %w", err)
	}

	salt := make([]byte, saltSize)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}
	aesKey, hmacKey := DeriveKeys(password, salt, settings)

	iv := make([]byte, blockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}

	header := make([]byte, 0)
	header = append(header, settingsSerialized...)
	header = append(header, salt...)
	header = append(header, iv...)
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
