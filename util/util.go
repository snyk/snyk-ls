package util

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/sirupsen/logrus"
	"os"
)

var Logger *logrus.Logger
var logFile *os.File

func InitLogging() {
	var err error
	logFile, err = os.OpenFile("/tmp/snyk-lsp.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		panic(err)
	}
	Logger = logrus.New()
	Logger.SetOutput(logFile)
}
func StopLogging() {
	defer logFile.Close()
}

func Hash(content string) string {
	bytes := sha256.Sum256([]byte(content))
	sum256 := hex.EncodeToString(bytes[:])
	return sum256
}
