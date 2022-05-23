package encoding

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func decodeBase64(enc []byte) ([]byte, error) {
	r := bytes.NewReader(enc)
	dec := base64.NewDecoder(base64.StdEncoding, r)

	result, err := ioutil.ReadAll(dec)
	return result, err
}

func deflate(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	data, err = ioutil.ReadAll(gr)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func TestEncoder(t *testing.T) {
	// prepare
	strToEncode := "Hello world"
	buf := new(bytes.Buffer)
	newEnc := NewEncoder(buf)

	// act
	_, err := newEnc.Write([]byte(strToEncode))
	if err != nil {
		t.Fatal(err)
	}

	// assert
	deflatedBytes, err := deflate(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := decodeBase64(deflatedBytes)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, strToEncode, string(decoded))
}
