<!--
SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>

SPDX-License-Identifier: MIT
-->

# scs
## SCS Codec Interface for session encryption and authentication using iocrypter

## Overview

The `scs` package provides an implementation of the Codec interface
for [Alex Edwards' SCS: HTTP Session Management](https://github.com/alexedwards/scs). It enables the use
of [iocrypter](https://github.com/wneessen/iocrypter) to encrypt and authenticate session data before storing 
them in any supported SCS session storage.

## Usage

### Importing

```go
package main

import (
	"log"
	"net/http"

	"github.com/alexedwards/scs/v2"
	scscrypter "github.com/wneessen/iocrypter/scs"
)

func main() {
	// Initialize a new session manager and set dbenc as Codec
	sessionManager = scs.New()
	sessionManager.Codec = scscrypter.New("VeryS3curE.P4ssPh4$3!")

	mux := http.NewServeMux()
	mux.HandleFunc("/session", yourSessionHandler)
	http.ListenAndServe(":4000", sessionManager.LoadAndSave(mux))
}
```

## License

This package is licensed under the MIT License. See [LICENSE](LICENSE) for details.
