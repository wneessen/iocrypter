// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package iocrypter

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"os"

	wa "github.com/wneessen/argon2"
)

// ErrTooLessRounds indicates that the provided number of rounds is smaller than the minimum
// required threshold.
var ErrTooLessRounds = errors.New("number of rounds too small")

func NewDecrypter(r io.Reader, password []byte) (io.ReadCloser, error) {
	aesKey, hmacKey, iv, header, err := readParameters(r, password)
	if err != nil {
		return nil, fmt.Errorf("failed to read encryption parameters: %w", err)
	}
	hasher := hmac.New(hashFunc, hmacKey)
	hasher.Write(header)

	// We need to write the reader contents into a temporary file to authenticate the HMAC
	tempFile, err := os.CreateTemp("", "iocrypter-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tempFile.Name())
	}()

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES block cipher: %w", err)
	}

	decrypter := io.NopCloser(&cipher.StreamReader{
		R: tempFile,
		S: cipher.NewCTR(block, iv),
	})
	checksum := make([]byte, hmacSize)
	writer := io.MultiWriter(hasher, tempFile)
	buffer := bufio.NewReaderSize(r, chunkSize)
	for {
		data, err := buffer.Peek(chunkSize)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("failed to read bytes from reader: %w", err)
		}

		// If we reached the end of the file, we read the rest of the buffered
		// bytes, store them in the writer and read the HMAC into the checksum
		// slice
		if errors.Is(err, io.EOF) {
			rest := buffer.Buffered()
			if rest < hmacSize {
				return nil, ErrMissingData
			}
			copy(checksum, data[rest-hmacSize:rest])
			_, err = io.CopyN(writer, buffer, int64(rest-hmacSize))
			if err != nil {
				return nil, fmt.Errorf("failed to rest of buffered bytes: %w", err)
			}
			break
		}

		_, err = io.CopyN(writer, buffer, int64(chunkSize-hmacSize))
		if err != nil {
			return nil, err
		}
	}

	// Authenticate the data
	if !hmac.Equal(checksum, hasher.Sum(nil)) {
		return nil, ErrFailedAuthentication
	}

	// Go back to the start of the file
	if _, err = tempFile.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to start of file: %w", err)
	}

	return decrypter, nil
}

// readParameters reads and deserializes the Argon2 settings, salt, IV, and derives keys from the provided
// reader and password.
func readParameters(r io.Reader, password []byte) ([]byte, []byte, []byte, []byte, error) {
	if len(password) == 0 {
		return nil, nil, nil, nil, ErrPassPhraseEmpty
	}
	settingsSerialized := make([]byte, wa.SerializedSettingsLength)
	if _, err := io.ReadFull(r, settingsSerialized); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read Argon2 settings: %w", err)
	}
	settings := wa.SettingsFromBytes(settingsSerialized)

	salt := make([]byte, settings.SaltLength)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read salt: %w", err)
	}

	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read IV: %w", err)
	}

	header := make([]byte, len(settingsSerialized)+len(salt)+len(iv))
	copy(header, settingsSerialized)
	copy(header[len(settingsSerialized):], salt)
	copy(header[len(settingsSerialized)+len(salt):], iv)
	if settings.Time < 1 {
		return nil, nil, nil, nil, ErrTooLessRounds
	}
	aesKey, hmacKey := DeriveKeys(password, salt, settings)

	return aesKey, hmacKey, iv, header, nil
}
