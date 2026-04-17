/*
 * © 2026 Snyk Limited
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

package code

import (
	"bytes"
	"encoding/json"
	"fmt"

	codeClientSarif "github.com/snyk/code-client-go/sarif"
)

// sarifRunHead is the first run object without results so json.Unmarshal skips the large results array.
type sarifRunHead struct {
	Tool       codeClientSarif.Tool          `json:"tool"`
	Properties codeClientSarif.RunProperties `json:"properties"`
}

type sarifDocumentHead struct {
	Schema  string         `json:"$schema"`
	Version string         `json:"version"`
	Runs    []sarifRunHead `json:"runs"`
}

func isDelim(tok json.Token, want json.Delim) bool {
	d, ok := tok.(json.Delim)
	return ok && d == want
}

// streamFirstRunResults walks sarifJSON (inner Sarif document) and decodes each result in runs[0].results.
func streamFirstRunResults(sarifJSON []byte, handle func(codeClientSarif.Result) error) error {
	dec := json.NewDecoder(bytes.NewReader(sarifJSON))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if !isDelim(tok, '{') {
		return fmt.Errorf("expected top-level JSON object")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("expected object key string")
		}
		if key != "runs" {
			if err := skipJSONValue(dec); err != nil {
				return err
			}
			continue
		}
		return consumeRunsArrayResults(dec, handle)
	}
	return nil
}

func consumeRunsArrayResults(dec *json.Decoder, handle func(codeClientSarif.Result) error) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if !isDelim(tok, '[') {
		return fmt.Errorf("runs: expected JSON array")
	}
	tok, err = dec.Token()
	if err != nil {
		return err
	}
	if isDelim(tok, ']') {
		return nil
	}
	if !isDelim(tok, '{') {
		return fmt.Errorf("runs: expected run object")
	}
	if err := consumeRunObjectResults(dec, handle); err != nil {
		return err
	}
	return finishRunsArrayAfterFirstRun(dec)
}

func consumeRunObjectResults(dec *json.Decoder, handle func(codeClientSarif.Result) error) error {
	for {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		if isDelim(keyTok, '}') {
			return nil
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("runs[0]: expected object key string")
		}
		switch key {
		case "results":
			if err := decodeResultsArray(dec, handle); err != nil {
				return err
			}
		default:
			if err := skipJSONValue(dec); err != nil {
				return err
			}
		}
	}
}

func finishRunsArrayAfterFirstRun(dec *json.Decoder) error {
	for dec.More() {
		var skipRun json.RawMessage
		if err := dec.Decode(&skipRun); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

func skipJSONValue(dec *json.Decoder) error {
	var skip json.RawMessage
	return dec.Decode(&skip)
}

func decodeResultsArray(dec *json.Decoder, handle func(codeClientSarif.Result) error) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if !isDelim(tok, '[') {
		return fmt.Errorf("results: expected JSON array")
	}
	for dec.More() {
		var res codeClientSarif.Result
		if decErr := dec.Decode(&res); decErr != nil {
			return decErr
		}
		if hErr := handle(res); hErr != nil {
			return hErr
		}
	}
	_, err = dec.Token()
	return err
}
