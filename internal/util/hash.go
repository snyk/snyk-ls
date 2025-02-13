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

package util

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"golang.org/x/net/html/charset"
)

func Hash(content []byte) string {
	reader := bytes.NewReader(content)
	utf8content, err := ConvertToUTF8(reader)
	if err != nil {
		utf8content = content
	}
	return HashWithoutConversion(utf8content)
}

func HashWithoutConversion(content []byte) string {
	b := sha256.Sum256(content)
	sum256 := hex.EncodeToString(b[:])
	return sum256
}

func ConvertToUTF8(reader io.Reader) ([]byte, error) {
	utf8Reader, err := charset.NewReaderLabel("UTF-8", reader)
	if err != nil {
		return nil, err
	}
	utf8content, err := io.ReadAll(utf8Reader)
	return utf8content, err
}

func Sha256First16Hash(input string) string {
	sum256 := Hash([]byte(input))
	return sum256[:16]
}
