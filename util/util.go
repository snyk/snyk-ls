package util

import (
	"crypto/sha256"
	"encoding/hex"
)

type ScanLevel int

const (
	FileLevel ScanLevel = iota + 1
	WorkspaceLevel
)

func Hash(content string) string {
	bytes := sha256.Sum256([]byte(content))
	sum256 := hex.EncodeToString(bytes[:])
	return sum256
}
