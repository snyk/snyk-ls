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

func compareChecksum(verifiedHashSum HashSum, filename string) error {
	h := sha256.New()

	r, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func(r *os.File) {
		_ = r.Close()
	}(r)

	log.Info().Msgf("copying %q to calculate checksum", filename)
	_, err = io.Copy(h, r)
	if err != nil {
		return err
	}

	calculatedSum := h.Sum(nil)
	if !bytes.Equal(calculatedSum, verifiedHashSum) {
		return fmt.Errorf("checksum mismatch (expected %q, calculated %q)",
			verifiedHashSum,
			hex.EncodeToString(calculatedSum))
	}

	log.Info().Msgf("checksum matches: %q", hex.EncodeToString(calculatedSum))

	return nil
}
