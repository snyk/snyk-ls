package util

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/sirupsen/logrus"
)

var Logger *logrus.Logger

func InitLogging() {
	Logger = logrus.New()
}

func Hash(content string) string {
	bytes := sha256.Sum256([]byte(content))
	sum256 := hex.EncodeToString(bytes[:])
	return sum256
}
