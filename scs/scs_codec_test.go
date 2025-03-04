package scs_codec

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/wneessen/iocrypter"
)

func TestNew(t *testing.T) {
	t.Run("New with password succeeds", func(t *testing.T) {
		passphrase := "verysecretkey"
		codec := New(passphrase)
		if codec == nil {
			t.Fatalf("creating new codec failed, codec is nil")
		}
		if !bytes.Equal(codec.pass, []byte(passphrase)) {
			t.Errorf("creating new codec failed, expected password to be: %q, got: %q", passphrase, codec.pass)
		}
	})
	t.Run("New with empty password fails", func(t *testing.T) {
		passphrase := ""
		codec := New(passphrase)
		if codec == nil {
			t.Fatalf("creating new codec failed, codec is nil")
		}
		_, err := codec.Encode(time.Now(), map[string]interface{}{})
		if err == nil {
			t.Errorf("expected encoding to fail with empty password")
		}
		if !errors.Is(err, iocrypter.ErrPassPhraseEmpty) {
			t.Errorf("expected error to be %s, got %s", iocrypter.ErrPassPhraseEmpty, err)
		}
	})
}

func TestCodec_Encode(t *testing.T) {
	passphrase := "verysecretkey"
	t.Run("encoding succeeds", func(t *testing.T) {
		codec := New(passphrase)
		if codec == nil {
			t.Fatalf("creating new codec failed, codec is nil")
		}
		data := map[string]interface{}{
			"foo": "bar",
		}
		encoded, err := codec.Encode(time.Now(), data)
		if err != nil {
			t.Errorf("encoding session data failed: %s", err)
		}
		if !bytes.Equal(encoded[:9], []byte{0x00, 0x00, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}) {
			t.Errorf("expected encoded data to start with magic bytes, got: %x", encoded[:9])
		}
	})
	t.Run("encoding with nil data", func(t *testing.T) {
		codec := New(passphrase)
		if codec == nil {
			t.Fatalf("creating new codec failed, codec is nil")
		}
		encoded, err := codec.Encode(time.Now(), nil)
		if err != nil {
			t.Errorf("encoding session data failed: %s", err)
		}
		if !bytes.Equal(encoded[:9], []byte{0x00, 0x00, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}) {
			t.Errorf("expected encoded data to start with magic bytes, got: %x", encoded[:9])
		}
	})
	t.Run("encoding with type alias fails", func(t *testing.T) {
		type Unknown int
		codec := New(passphrase)
		if codec == nil {
			t.Fatalf("creating new codec failed, codec is nil")
		}
		data := map[string]interface{}{
			"foo": Unknown(1),
		}
		_, err := codec.Encode(time.Now(), data)
		if err == nil {
			t.Errorf("expected encoding to fail with unregistered type alias")
		}
	})
}

func TestCodec_Decode(t *testing.T) {
	passphrase := "verysecretkey"
	now := time.Now()
	codec := New(passphrase)
	if codec == nil {
		t.Fatalf("creating new codec failed, codec is nil")
	}
	data := map[string]interface{}{
		"foo": "bar",
	}
	encoded, err := codec.Encode(now, data)
	if err != nil {
		t.Fatalf("encoding session data failed: %s", err)
	}

	t.Run("decoding succeeds", func(t *testing.T) {
		timestamp, decoded, err := codec.Decode(encoded)
		if err != nil {
			t.Errorf("decoding session data failed: %s", err)
		}
		if !now.Equal(timestamp) {
			t.Errorf("expected timestamp to be equal want: %s, got: %s", now.String(), timestamp.String())
		}
		decodedData, ok := decoded["foo"]
		if !ok {
			t.Fatalf("expected decoded data to contain key 'foo'")
		}
		if decodedData != "bar" {
			t.Errorf("expected decoded data to contain value 'bar', got: %s", decodedData)
		}
	})
	t.Run("decoding fails with wrong passphrase", func(t *testing.T) {
		codec.pass = []byte("wrongpassphrase")
		t.Cleanup(func() { codec.pass = []byte(passphrase) })
		_, _, err := codec.Decode(encoded)
		if err == nil {
			t.Errorf("expected decoding to fail with wrong passphrase")
		}
		if !errors.Is(err, iocrypter.ErrFailedAuthentication) {
			t.Errorf("expected error to be %s, got %s", iocrypter.ErrFailedAuthentication, err)
		}
	})
	t.Run("decoding with nil data", func(t *testing.T) {
		_, _, err := codec.Decode(nil)
		if err == nil {
			t.Errorf("expected decoding to fail with nil data")
		}
	})
	t.Run("decoding fails with non-gobed data", func(t *testing.T) {
		encrypter, err := iocrypter.NewEncrypter(bytes.NewBufferString("teststringthatis"), []byte(passphrase))
		if err != nil {
			t.Fatalf("failed to create encrypter: %s", err)
		}
		buffer := bytes.NewBuffer(nil)
		if _, err = io.Copy(buffer, encrypter); err != nil {
			t.Fatalf("failed to encrypt data: %s", err)
		}
		_, _, err = codec.Decode(buffer.Bytes())
		if err == nil {
			t.Errorf("expected decoding to fail with non-gobed data")
		}
	})
}

func BenchmarkCodec_Encode(b *testing.B) {
	passphrase := "verysecretkey"
	codec := New(passphrase)
	if codec == nil {
		b.Fatalf("creating new codec failed, codec is nil")
	}
	data := map[string]interface{}{
		"foo": "bar",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := codec.Encode(time.Now(), data)
		if err != nil {
			b.Fatalf("encoding session data failed: %s", err)
		}
	}
}

func BenchmarkCodec_Decode(b *testing.B) {
	passphrase := "verysecretkey"
	codec := New(passphrase)
	if codec == nil {
		b.Fatalf("creating new codec failed, codec is nil")
	}
	data := map[string]interface{}{
		"foo": "bar",
	}
	encoded, err := codec.Encode(time.Now(), data)
	if err != nil {
		b.Fatalf("encoding session data failed: %s", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := codec.Decode(encoded)
		if err != nil {
			b.Fatalf("decoding session data failed: %s", err)
		}
	}
}
