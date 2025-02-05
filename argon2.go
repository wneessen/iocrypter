// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package iocrypter

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// defaultArgon2Treads defines the default number of threads for the Argon2 key
	// derivation function.
	defaultArgon2Treads = 4

	// defaultArgon2Memory defines the default memory in kibibytes for the Argon2 key
	// derivation function.
	defaultArgon2Memory = 64 * 1024

	// defaultArgon2Time defines the default number of iterations for the Argon2 key
	// derivation function.
	defaultArgon2Time = 1
)

// Argon2Settings represents configuration parameters for the Argon2 password hashing
// algorithm.
type Argon2Settings struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

// NewArgon2Settings creates a new Argon2Settings instance with default parameters for time, memory, and threads.
func NewArgon2Settings() Argon2Settings {
	return NewArgon2SettingsWithSettings(defaultArgon2Time, defaultArgon2Memory, defaultArgon2Treads)
}

// NewArgon2SettingsWithSettings creates a new Argon2Settings instance with the provided time, memory,
// and thread values.
func NewArgon2SettingsWithSettings(time, memory uint32, threads uint8) Argon2Settings {
	return Argon2Settings{
		Memory:  memory,
		Threads: threads,
		Time:    time,
	}
}

// DeriveKeys will use Argon2id to derive a AES-256 and a HMAC key from the
// given password and salt. It will use the given Argon2Settings for the key derivation.
func DeriveKeys(password, salt []byte, settings Argon2Settings) ([]byte, []byte) {
	key := argon2.IDKey(password, salt, settings.Time, settings.Memory, settings.Threads, saltSize+hmacSize)
	return key[:aesKeySize], key[aesKeySize : hmacKeySize+aesKeySize]
}

// Encode serializes the Argon2Settings struct into a byte slice using binary encoding and returns the result
// or an error.
func (a Argon2Settings) Encode() ([]byte, error) {
	buffer := bytes.NewBuffer(nil)
	if err := binary.Write(buffer, binary.LittleEndian, a.Memory); err != nil {
		return nil, fmt.Errorf("failed to binary encode Argon2 memory setting: %w", err)
	}
	if err := binary.Write(buffer, binary.LittleEndian, a.Threads); err != nil {
		return nil, fmt.Errorf("failed to binary encode Argon2 threads setting: %w", err)
	}
	if err := binary.Write(buffer, binary.LittleEndian, a.Time); err != nil {
		return nil, fmt.Errorf("failed to binary encode Argon2 threads setting: %w", err)
	}
	return buffer.Bytes(), nil
}

// DeserializeSettings decodes a byte slice into an Argon2Settings struct using binary encoding and returns
// it or an error.
func DeserializeSettings(b []byte) (Argon2Settings, error) {
	settings := Argon2Settings{}
	reader := bytes.NewReader(b)
	if err := binary.Read(reader, binary.LittleEndian, &settings.Memory); err != nil {
		return settings, fmt.Errorf("failed to binary decode Argon2 memory setting: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &settings.Threads); err != nil {
		return settings, fmt.Errorf("failed to binary decode Argon2 threads setting: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &settings.Time); err != nil {
		return settings, fmt.Errorf("failed to binary decode Argon2 time setting: %w", err)
	}
	return settings, nil
}
