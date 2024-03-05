/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

	if err = b64Writer.Close(); err != nil {
		return n, err
	}
	if err = zipWriter.Close(); err != nil {
		return n, err
	}

	return n, err
}
