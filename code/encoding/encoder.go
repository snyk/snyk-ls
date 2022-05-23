package encoding

import (
	"compress/gzip"
	"encoding/base64"
	"io"
)

type EncoderWriter struct {
	w io.Writer
}

// NewEncoder returns a new EncoderWriter.
// Writes to the returned writer are base64 encoded, compressed and written to w.
func NewEncoder(w io.Writer) *EncoderWriter {
	enc := new(EncoderWriter)
	enc.w = w
	return enc
}

func (ew *EncoderWriter) Write(b []byte) (int, error) {
	zipWriter := gzip.NewWriter(ew.w)
	b64Writer := base64.NewEncoder(base64.StdEncoding, zipWriter)

	n, err := b64Writer.Write(b)
	if err != nil {
		return n, err
	}
	b64Writer.Close()

	if err := zipWriter.Close(); err != nil {
		return n, err
	}

	return n, err
}
