// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package iocrypter

import (
	"bytes"
	"hash"
	"io"
)

// hashReadWriter is a type that implements io.ReadWriter using a hash.Hash instance for data hashing.
// It disallows further writes once reading begins. The hashing result is provided as an io.Reader
// after writes are complete.
type hashReadWriter struct {
	hash     hash.Hash
	done     bool
	checksum io.Reader
}

// NewHashReadWriter creates and returns an io.ReadWriter that uses the provided hash.Hash instance
// for data hashing. Note that writing to the returned instance is disallowed after read operations
// have begun.
func NewHashReadWriter(hash hash.Hash) io.ReadWriter {
	return &hashReadWriter{hash: hash}
}

// Write satisfies the io.Writer interface for the hashReadWriter type. It writes the provided byte
// slice to the underlying hash.Hash. Returns an error if writing is attempted after reading.
func (h *hashReadWriter) Write(p []byte) (int, error) {
	if h.done {
		return 0, ErrWriteAfterRead
	}
	return h.hash.Write(p)
}

// Read satisfies the io.Reader interface for the hashReadWriter type. It allows data to be read from
// the hash result after writes are complete. It initializes the hash checksum as a reader on the first call
// and restricts further writes.
func (h *hashReadWriter) Read(p []byte) (int, error) {
	if !h.done {
		h.done = true
		h.checksum = bytes.NewReader(h.hash.Sum(nil))
	}
	return h.checksum.Read(p)
}
