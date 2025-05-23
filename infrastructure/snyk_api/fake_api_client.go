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

package snyk_api

import (
	"sync"
)

const (
	SastEnabledOperation = "sastEnabled"
)

type FakeApiClient struct {
	Calls          map[string][][]any
	CodeEnabled    bool
	AutofixEnabled bool
	ApiError       *SnykApiError
	Responses      map[string]any
}

var (
	mutex = &sync.Mutex{}
)

func (f *FakeApiClient) SetResponse(method string, response any) {
	if f.Responses == nil {
		f.Responses = make(map[string]any)
	}
	f.Responses[method] = response
}

func (f *FakeApiClient) addCallForMethod(method string, args []any) {
	mutex.Lock()
	defer mutex.Unlock()

	if f.Calls == nil {
		f.Calls = make(map[string][][]any)
	}
	f.Calls[method] = append(f.Calls[method], args)
}

func (f *FakeApiClient) GetCallParams(callNo int, op string) []any {
	mutex.Lock()
	defer mutex.Unlock()
	calls := f.Calls[op]
	if calls == nil {
		return nil
	}
	params := calls[callNo]
	if params == nil {
		return nil
	}
	return params
}

func (f *FakeApiClient) Clear() {
	mutex.Lock()
	defer mutex.Unlock()

	f.Calls = map[string][][]any{}
	f.Responses = map[string]any{}
}

func (f *FakeApiClient) GetAllCalls(op string) [][]any {
	mutex.Lock()
	defer mutex.Unlock()
	calls := f.Calls[op]
	if calls == nil {
		return nil
	}
	return calls
}

func (f *FakeApiClient) FeatureFlagStatus(featureFlagType FeatureFlagType) (FFResponse, error) {
	f.addCallForMethod("FeatureFlagStatus", []any{featureFlagType})

	if resp, ok := f.Responses["FeatureFlagStatus"]; ok {
		if ffResp, ok := resp.(FFResponse); ok {
			return ffResp, nil
		}
	}
	return FFResponse{}, nil
}
