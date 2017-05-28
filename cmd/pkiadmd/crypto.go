package main

import (
	"crypto/sha512"
	"encoding/base64"
)

func Hash(in []byte) []byte {
	raw := sha512.Sum512(in)
	return []byte(base64.StdEncoding.EncodeToString(raw[:]))
}
