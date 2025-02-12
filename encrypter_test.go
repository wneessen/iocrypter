// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package iocrypter

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
)

// testPassword is a constant string representing a password used for testing purposes.
var testPassword = []byte(`:wPIuo[F#Gnh6*lmzc'_bmYpY!UV)Tt1`)

func TestNewEncrypter(t *testing.T) {
	t.Run("normal encrypter creation", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		encrypter, err := NewEncrypter(buffer, testPassword)
		if err != nil {
			t.Fatalf("failed to create encrypter: %s", err)
		}
		if encrypter == nil {
			t.Fatal("encrypter is nil")
		}
	})
	t.Run("encrypter creation with nil passphrase should fail", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		_, err := NewEncrypter(buffer, nil)
		if err == nil {
			t.Fatal("expected encrypter creation to fail with nil passphrase")
		}
		if !errors.Is(err, ErrPassPhraseEmpty) {
			t.Errorf("expected error to be %s, got %s", ErrPassPhraseEmpty, err)
		}
	})
}

func TestNewEncrypterWithSettings(t *testing.T) {
	t.Run("normal encrypter creation", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		encrypter, err := NewEncrypterWithSettings(buffer, testPassword, NewArgon2Settings())
		if err != nil {
			t.Fatalf("failed to create encrypter: %s", err)
		}
		if encrypter == nil {
			t.Fatal("encrypter is nil")
		}
	})
	t.Run("encrypter creation fails with broken random reader", func(t *testing.T) {
		defaultRandReader := rand.Reader
		t.Cleanup(func() { rand.Reader = defaultRandReader })
		rand.Reader = &failReadWriter{failOnRead: 0}

		buffer := bytes.NewBuffer(nil)
		_, err := NewEncrypterWithSettings(buffer, testPassword, NewArgon2Settings())
		if err == nil {
			t.Fatal("expected encrypter creation to fail with broken random reader")
		}
		expErr := "failed to generate random salt"
		if !strings.Contains(err.Error(), expErr) {
			t.Errorf("expected error to contain %s, got %s", expErr, err)
		}
	})
	t.Run("encrypter creation fails with broken random reader on 2nd read", func(t *testing.T) {
		defaultRandReader := rand.Reader
		t.Cleanup(func() { rand.Reader = defaultRandReader })
		rand.Reader = &failReadWriter{failOnRead: 1}

		buffer := bytes.NewBuffer(nil)
		_, err := NewEncrypterWithSettings(buffer, testPassword, NewArgon2Settings())
		if err == nil {
			t.Fatal("expected encrypter creation to fail with broken random reader")
		}
		expErr := "failed to generate random iv"
		if !strings.Contains(err.Error(), expErr) {
			t.Errorf("expected error to contain %s, got %s", expErr, err)
		}
	})
	t.Run("encrypter fails encrypting into broken writer", func(t *testing.T) {
		buffer := bytes.NewBufferString("This is a test")
		encrypter, err := NewEncrypterWithSettings(buffer, testPassword, NewArgon2Settings())
		if err != nil {
			t.Fatalf("failed to create encrypter: %s", err)
		}

		reader := &failReadWriter{failOnRead: 0}
		if _, err = io.Copy(reader, encrypter); err == nil {
			t.Error("expected encrypter to fail with broken writer")
		}
	})
	t.Run("encrypter fails encrypting from broken reader", func(t *testing.T) {
		reader := &failReadWriter{failOnRead: 0}
		encrypter, err := NewEncrypterWithSettings(reader, testPassword, NewArgon2Settings())
		if err != nil {
			t.Fatalf("failed to create encrypter: %s", err)
		}

		buffer := bytes.NewBuffer(nil)
		if _, err = io.Copy(buffer, encrypter); err == nil {
			t.Error("expected encrypter to fail with broken reader")
		}
	})
}

// failReadWriter is type that satisfies the io.ReadWriter interface. All it does is fail
// on the Read and Write operation. It can fail on a specific read operations and is
// therefore useful to test consecutive reads with errors.
type failReadWriter struct {
	failOnRead  uint8
	currentRead uint8
}

// Read implements the io.Reader interface for the failReadWriter type
func (r *failReadWriter) Read(p []byte) (int, error) {
	if r.currentRead == r.failOnRead {
		return 0, errors.New("intentionally failing")
	}
	r.currentRead++
	return len(p), nil
}

// Write implements the io.Writer interface for the failReadWriter type
func (r *failReadWriter) Write([]byte) (int, error) {
	return 0, errors.New("intentionally failing")
}
