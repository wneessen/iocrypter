// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/wneessen/iocrypter"
)

func main() {
	var inFile, outFile, password string
	flag.StringVar(&inFile, "i", "", "path to encrypted input file")
	flag.StringVar(&outFile, "o", "", "path to output file")
	flag.StringVar(&password, "p", "", "encryption password")
	flag.Parse()
	if flag.NFlag() != 3 {
		_, _ = fmt.Fprintf(os.Stderr, "usage: %s -i <input file> -o <output file> -p <password>\n", os.Args[0])
		os.Exit(1)
	}

	input, err := os.Open(inFile)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to open input file: %s\n", err)
		os.Exit(1)
	}
	defer func() {
		if deferErr := input.Close(); deferErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to close input file: %s\n", deferErr)
		}
	}()

	output, err := os.Create(outFile)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to create output file: %s\n", err)
		os.Exit(1)
	}
	defer func() {
		if deferErr := output.Close(); deferErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to close output file: %s\n", deferErr)
		}
	}()

	decrypter, err := iocrypter.NewDecrypter(input, []byte(password))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to create decrypter: %s\n", err)
		os.Exit(1)
	}

	startTime := time.Now()
	_, err = io.Copy(output, decrypter)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to decrypt data: %s\n", err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintf(os.Stderr, "File %s successfully decrypted to: %s (Time: %s)\n", input.Name(), output.Name(),
		time.Since(startTime).String())
}
