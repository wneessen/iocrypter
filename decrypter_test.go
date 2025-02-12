// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package iocrypter

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestNewDecrypter(t *testing.T) {
	plaintext := "This is the plaintext"
	plainbuf := bytes.NewBufferString(plaintext)
	encrypter, err := NewEncrypter(plainbuf, testPassword)
	if err != nil {
		t.Fatalf("failed to create encrypter: %s", err)
	}
	buffer := bytes.NewBuffer(nil)
	if _, err = io.Copy(buffer, encrypter); err != nil {
		t.Fatalf("failed to encrypt plaintext: %s", err)
	}
	ciphertext := buffer.Bytes()

	t.Run("normal encrypt/decrypt operation", func(t *testing.T) {
		ciphertextbuf := bytes.NewBuffer(ciphertext)
		decrypter, err := NewDecrypter(ciphertextbuf, testPassword)
		if err != nil {
			t.Fatalf("failed to create decrypter: %s", err)
		}
		decrypted := bytes.NewBuffer(nil)
		if _, err = io.Copy(decrypted, decrypter); err != nil {
			t.Errorf("failed to decrypt ciphertext: %s", err)
		}
		if !strings.EqualFold(plaintext, decrypted.String()) {
			t.Errorf("plaintext and ciphertext do not match, expected %s, got %s", plaintext,
				decrypted.String())
		}
	})
	t.Run("decrypter creation with nil passphrase should fail", func(t *testing.T) {
		ciphertextbuf := bytes.NewBuffer(ciphertext)
		_, err := NewDecrypter(ciphertextbuf, nil)
		if err == nil {
			t.Fatal("expected decrypter creation to fail with nil passphrase")
		}
	})
	t.Run("decryption with invalid passphrase should fail", func(t *testing.T) {
		ciphertextbuf := bytes.NewBuffer(ciphertext)
		_, err := NewDecrypter(ciphertextbuf, []byte("invalid passphrase"))
		if err == nil {
			t.Errorf("expected decryption to fail with invalid passphrase")
		}
		if !errors.Is(err, ErrFailedAuthentication) {
			t.Errorf("expected error to be %s, got %s", ErrFailedAuthentication, err)
		}
	})
}
