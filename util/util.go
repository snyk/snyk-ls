package util

import (
	"crypto/sha256"
	"encoding/hex"
)

func Hash(content string) string {
	bytes := sha256.Sum256([]byte(content))
	sum256 := hex.EncodeToString(bytes[:])
	return sum256
}
