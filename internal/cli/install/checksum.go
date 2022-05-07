package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
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

func compareChecksum(ctx context.Context, expectedSum HashSum, filename string) error {
	calculatedSum, err := getChecksum(ctx, filename)
	if err != nil {
		return err
	}

	if !bytes.Equal(calculatedSum, expectedSum) {
		return fmt.Errorf("checksum mismatch (expected %q, calculated %q)",
			expectedSum,
			hex.EncodeToString(calculatedSum))
	}

	logger.
		WithField("method", "compareChecksum").
		Debug(ctx, "checksum matches:"+hex.EncodeToString(calculatedSum))

	return nil
}

func getChecksum(ctx context.Context, filename string) ([]byte, error) {
	h := sha256.New()

	r, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func(r *os.File) {
		_ = r.Close()
	}(r)

	logger.
		WithField("method", "getChecksum").
		WithField("fileName", filename).
		Info(ctx, "copying file to calculate checksum")
	_, err = io.Copy(h, r)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
