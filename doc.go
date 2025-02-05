// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package iocrypter implements AES-256-CTR encryption with SHA-512 HMAC Authentication
// as a io.Reader interface. It allows the en- and decryption with authentication of
// arbitrary data from a given io.Reader.
//
// It derives a secure key for the AES-256 encryption using Argon2ID. Encryption
// parameters like the Argon2 settings, the salt and the IV are stored in the beginning
// of the ciphertext, making it convenient for byte stream encryption.
package iocrypter
