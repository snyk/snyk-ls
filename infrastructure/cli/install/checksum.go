package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog/log"
)

type HashSum []byte

func (hs HashSum) String() string {
	return hex.EncodeToString(hs)
}

func HashSumFromHexDigest(hexDigest string) (HashSum, error) {
	sumBytes, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, err
	}
	return sumBytes, nil
}

func compareChecksum(expectedSum HashSum, filename string) error {
	calculatedSum, err := getChecksum(filename)
	if err != nil {
		return err
	}

	if !bytes.Equal(calculatedSum, expectedSum) {
		return fmt.Errorf("checksum mismatch (expected %q, calculated %q)",
			expectedSum,
			hex.EncodeToString(calculatedSum))
	}

	log.Info().Msgf("checksum matches: %q", hex.EncodeToString(calculatedSum))

	return nil
}

func getChecksum(filename string) ([]byte, error) {
	h := sha256.New()

	r, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func(r *os.File) {
		_ = r.Close()
	}(r)

	log.Info().Msgf("copying %q to calculate checksum", filename)
	_, err = io.Copy(h, r)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
