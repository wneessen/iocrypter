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
	t.Run("decryption with invalid argon2 settings should fail", func(t *testing.T) {
		ciphertextbuf := bytes.NewBuffer([]byte{0o0, 0o1, 0o2, 0o3})
		_, err := NewDecrypter(ciphertextbuf, testPassword)
		if err == nil {
			t.Errorf("expected decryption to fail with invalid argon2 settings")
		}
		expErr := "failed to read Argon2 settings"
		if !strings.Contains(err.Error(), expErr) {
			t.Errorf("expected error to contain %s, got %s", expErr, err)
		}
	})
	t.Run("decryption with invalid salt should fail", func(t *testing.T) {
		settings := testSettings.Serialize()
		ciphertextbuf := bytes.NewBuffer(append(settings, []byte{0o0, 0o1, 0o2, 0o3}...))
		_, err = NewDecrypter(ciphertextbuf, testPassword)
		if err == nil {
			t.Errorf("expected decryption to fail with invalid salt")
		}
		expErr := "failed to read salt"
		if !strings.Contains(err.Error(), expErr) {
			t.Errorf("expected error to contain %s, got %s", expErr, err)
		}
	})
	t.Run("decryption with invalid iv should fail", func(t *testing.T) {
		settings := testSettings.Serialize()
		salt := make([]byte, saltSize)
		cipherdata := append(settings, salt...)
		ciphertextbuf := bytes.NewBuffer(append(cipherdata, []byte{0o0, 0o1, 0o2, 0o3}...))
		_, err = NewDecrypter(ciphertextbuf, testPassword)
		if err == nil {
			t.Errorf("expected decryption to fail with invalid IV")
		}
		expErr := "failed to read IV"
		if !strings.Contains(err.Error(), expErr) {
			t.Errorf("expected error to contain %s, got %s", expErr, err)
		}
	})
	t.Run("decryption with tampered ciphertext should fail", func(t *testing.T) {
		ciphertextbuf := bytes.NewBuffer(ciphertext[:len(ciphertext)-1])
		_, err = NewDecrypter(ciphertextbuf, testPassword)
		if err == nil {
			t.Errorf("expected decryption to fail with tampered ciphertext")
		}
		if !errors.Is(err, ErrFailedAuthentication) {
			t.Errorf("expected error to be %s, got %s", ErrFailedAuthentication, err)
		}
	})
	t.Run("decryption with missing checksum should fail", func(t *testing.T) {
		ciphertextbuf := bytes.NewBuffer(ciphertext[:len(ciphertext)-hmacSize])
		_, err = NewDecrypter(ciphertextbuf, testPassword)
		if err == nil {
			t.Errorf("expected decryption to fail with missing checksum")
		}
		if !errors.Is(err, ErrMissingData) {
			t.Errorf("expected error to be %s, got %s", ErrMissingData, err)
		}
	})
	t.Run("decryption on broken reader should fail", func(t *testing.T) {
		ciphertextbuf := &failReadWriter{failOnRead: 3}
		ciphertextbuf.readFunc = func(p []byte) (int, error) {
			settings := testSettings.Serialize()
			if ciphertextbuf.currentRead-1 == 0 {
				copy(p, settings)
			}
			return len(p), nil
		}
		_, err = NewDecrypter(ciphertextbuf, testPassword)
		if err == nil {
			t.Errorf("expected decryption to fail with broken reader")
		}
		if !strings.Contains(err.Error(), "intentionally failing") {
			t.Errorf("expected error to contain 'intentionally failing', got %s", err)
		}
	})
	t.Run("decryption on broken reader with too low argon2 rounds should fail", func(t *testing.T) {
		ciphertextbuf := &failReadWriter{failOnRead: 3}
		ciphertextbuf.readFunc = func(p []byte) (int, error) {
			settings := testSettings
			settings.Time = 0
			settingsBytes := settings.Serialize()
			if ciphertextbuf.currentRead-1 == 0 {
				copy(p, settingsBytes)
			}
			return len(p), nil
		}
		_, err = NewDecrypter(ciphertextbuf, testPassword)
		if err == nil {
			t.Errorf("expected decryption to fail with too low argon2 rounds")
		}
		if !errors.Is(err, ErrTooLessRounds) {
			t.Errorf("expected error to be %s, got %s", ErrTooLessRounds, err)
		}
	})
}
