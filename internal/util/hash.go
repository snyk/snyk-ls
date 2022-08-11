package util

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"golang.org/x/net/html/charset"
)

func Hash(content []byte) string {
	byteReader := bytes.NewReader(content)
	reader, _ := charset.NewReaderLabel("UTF-8", byteReader)
	utf8content, err := io.ReadAll(reader)
	if err != nil {
		utf8content = content
	}
	b := sha256.Sum256(utf8content)
	sum256 := hex.EncodeToString(b[:])
	return sum256
}
