package iocrypter

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewArgon2Settings(t *testing.T) {
	settings := NewArgon2Settings()
	if settings.Memory != defaultArgon2Memory {
		t.Errorf("expected memory setting to be: %d, got: %d", defaultArgon2Memory, settings.Memory)
	}
	if settings.Threads != defaultArgon2Threads {
		t.Errorf("expected threads setting to be: %d, got: %d", defaultArgon2Threads, settings.Threads)
	}
	if settings.Time != defaultArgon2Time {
		t.Errorf("expected time setting to be: %d, got: %d", defaultArgon2Time, settings.Time)
	}
}

func TestNewArgon2SettingsWithSettings(t *testing.T) {
	time := uint32(5678)
	memory := uint32(1234)
	threads := uint8(5)
	settings := NewArgon2SettingsWithSettings(time, memory, threads)
	if settings.Memory != memory {
		t.Errorf("expected memory setting to be: %d, got: %d", memory, settings.Memory)
	}
	if settings.Threads != threads {
		t.Errorf("expected threads setting to be: %d, got: %d", threads, settings.Threads)
	}
	if settings.Time != time {
		t.Errorf("expected time setting to be: %d, got: %d", time, settings.Time)
	}
}

func TestDeriveKeys(t *testing.T) {
	pass := []byte("password")
	salt := []byte("salt")
	const (
		aesExpect  = "8cbce4bf751fb198f0f93b3e118c76cf7b41d4c06293096a8a61501bfb22840d"
		hmacExpect = "e012fe7a7a4023adddc8ab81ad98b6569e5af86c4e57542fca60afcea0c2ff84"
	)
	settings := NewArgon2Settings()
	aesKey, hmacKey := DeriveKeys(pass, salt, settings)
	if len(aesKey) != aesKeySize {
		t.Errorf("expected AES key length to be: %d, got: %d", aesKeySize, len(aesKey))
	}
	if len(hmacKey) != hmacKeySize {
		t.Errorf("expected HMAC key length to be: %d, got: %d", hmacKeySize, len(hmacKey))
	}
	if !strings.EqualFold(aesExpect, hex.EncodeToString(aesKey)) {
		t.Errorf("expected AES key to be: %s, got: %s", aesExpect, hex.EncodeToString(aesKey))
	}
	if !strings.EqualFold(hmacExpect, hex.EncodeToString(hmacKey)) {
		t.Errorf("expected HMAC key to be: %s, got: %s", hmacExpect, hex.EncodeToString(hmacKey))
	}
}

func TestArgon2Settings_Encode(t *testing.T) {
	t.Run("encode default settings", func(t *testing.T) {
		settings := NewArgon2Settings()
		encoded, err := settings.Encode()
		if err != nil {
			t.Errorf("failed to encode Argon2 settings: %s", err)
		}
		if len(encoded) != 9 {
			t.Errorf("expected encoded settings length to be: %d, got: %d", 9, len(encoded))
		}
	})
	t.Run("encode custom settings", func(t *testing.T) {
		time := uint32(5678)
		memory := uint32(1234)
		threads := uint8(5)
		settings := NewArgon2SettingsWithSettings(time, memory, threads)
		encoded, err := settings.Encode()
		if err != nil {
			t.Errorf("failed to encode Argon2 settings: %s", err)
		}
		if len(encoded) != 9 {
			t.Errorf("expected encoded settings length to be: %d, got: %d", 9, len(encoded))
		}
	})
	t.Run("encode with invalid memory setting", func(t *testing.T) {
		settings := NewArgon2SettingsWithSettings(4_294_967_295, 0, 0)
		_, err := settings.Encode()
		if err == nil {
			t.Errorf("expected encoding to fail")
		}
		t.Log(err)
	})
}

func TestDeserializeSettings(t *testing.T) {
	t.Run("deserialize default settings", func(t *testing.T) {
		settings := NewArgon2Settings()
		encoded, err := settings.Encode()
		if err != nil {
			t.Fatalf("failed to encode Argon2 settings: %s", err)
		}
		deserialized, err := DeserializeSettings(encoded)
		if err != nil {
			t.Fatalf("failed to deserialize Argon2 settings: %s", err)
		}
		if settings.Memory != deserialized.Memory {
			t.Errorf("expected deserialized memory setting to be: %d, got: %d", settings.Memory,
				deserialized.Memory)
		}
		if settings.Threads != deserialized.Threads {
			t.Errorf("expected deserialized threads setting to be: %d, got: %d", settings.Threads,
				deserialized.Threads)
		}
		if settings.Time != deserialized.Time {
			t.Errorf("expected deserialized time setting to be: %d, got: %d", settings.Time,
				deserialized.Time)
		}
	})
	t.Run("deserialize custom settings", func(t *testing.T) {
		time := uint32(5678)
		memory := uint32(1234)
		threads := uint8(5)
		settings := NewArgon2SettingsWithSettings(time, memory, threads)
		encoded, err := settings.Encode()
		if err != nil {
			t.Fatalf("failed to encode Argon2 settings: %s", err)
		}
		deserialized, err := DeserializeSettings(encoded)
		if err != nil {
			t.Fatalf("failed to deserialize Argon2 settings: %s", err)
		}
		if memory != deserialized.Memory {
			t.Errorf("expected deserialized memory setting to be: %d, got: %d", memory, deserialized.Memory)
		}
		if threads != deserialized.Threads {
			t.Errorf("expected deserialized threads setting to be: %d, got: %d", threads, deserialized.Threads)
		}
		if time != deserialized.Time {
			t.Errorf("expected deserialized time setting to be: %d, got: %d", time, deserialized.Time)
		}
	})
	t.Run("deserialize with invalid memory setting", func(t *testing.T) {
		invalidSettings := []byte{0xFF}
		_, err := DeserializeSettings(invalidSettings)
		if err == nil {
			t.Errorf("expected deserialization to fail")
		}
	})
	t.Run("deserialize with invalid threads setting", func(t *testing.T) {
		invalidSettings := []byte{0x00, 0x01, 0x04, 0xFF}
		_, err := DeserializeSettings(invalidSettings)
		if err == nil {
			t.Errorf("expected deserialization to fail")
		}
	})
	t.Run("deserialize with invalid time setting", func(t *testing.T) {
		invalidSettings := []byte{0x00, 0x00, 0x01, 0x04, 0xFF}
		_, err := DeserializeSettings(invalidSettings)
		if err == nil {
			t.Errorf("expected deserialization to fail")
		}
	})
}
