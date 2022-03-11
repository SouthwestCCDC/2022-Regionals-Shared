package main

import (
	"encoding/hex"
	"strings"
)

// fromHexChar converts a hex character into its value and a success flag.
func fromHexChar(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}

	return 0, false
}

// decodeUppercaseHex decodes src into hex.DecodedLen(len(src)) bytes,
// returning the actual number of bytes written to dst.
//
// Decode expects that src contain only hexadecimal
// characters and that src should have an even length.
func decodeUppercaseHex(dst, src []byte) (int, error) {
	if len(src)%2 == 1 {
		return 0, hex.ErrLength
	}

	for i := 0; i < len(src)/2; i++ {
		a, ok := fromHexChar(src[i*2])
		if !ok {
			return 0, hex.InvalidByteError(src[i*2])
		}
		b, ok := fromHexChar(src[i*2+1])
		if !ok {
			return 0, hex.InvalidByteError(src[i*2+1])
		}
		dst[i] = (a << 4) | b
	}

	return len(src) / 2, nil
}

// decodeUppercaseHexString returns the bytes represented by the hexadecimal
// string s.
func decodeUppercaseHexString(s string) ([]byte, error) {
	src := []byte(s)
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err := decodeUppercaseHex(dst, src)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func hexToStrings(h string) ([]string, error) {
	output, err := decodeUppercaseHexString(h)
	if err != nil {
		return nil, err
	}

	return strings.Split(string(output), "\x00"), nil
}
