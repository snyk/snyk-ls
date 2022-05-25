package util

import (
	"crypto/sha256"
	"encoding/hex"
)

func Hash(content []byte) string {
	bytes := sha256.Sum256(content)
	sum256 := hex.EncodeToString(bytes[:])
	return sum256
}
