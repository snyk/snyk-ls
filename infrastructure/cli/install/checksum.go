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
	defer func(r *os.File) { _ = r.Close() }(r)

	log.Info().Msgf("copying %q to calculate checksum", filename)
	_, err = io.Copy(h, r)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
