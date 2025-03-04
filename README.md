<!--
SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>

SPDX-License-Identifier: MIT
-->

# iocrypter

iocrypter is a Go package that implements AES-256-CTR encryption with SHA-512 HMAC authentication
as a `io.Reader` interface. It allows the en- and decryption with authentication of arbitrary data 
from any given `io.Reader`.

It derives a secure key for the AES-256 encryption using Argon2ID. Encryption parameters like the 
Argon2 settings, the salt and the IV are stored at the start of the ciphertext, making it convenient 
for byte stream encryption.

The [cmd/](cmd) directory holds two example implementations for tools that will read a file from
disk and then en- or decrypt it accordingly.

The [scs](scs) directory holds a package that provides an implementation of the
[Codec interface](https://pkg.go.dev/github.com/alexedwards/scs/v2#Codec) for
[Alex Edwards' SCS: HTTP Session Management](https://github.com/alexedwards/scs). It enables the use
of iocrypter to encrypt and authenticate session data before storing them in any supported SCS
session storage.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
