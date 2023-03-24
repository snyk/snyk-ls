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

import "sync"

const (
	SastEnabledOperation = "sastEnabled"
	ActiveUserOperation  = "activeUser"
)

type FakeApiClient struct {
	Calls       map[string][][]any
	CodeEnabled bool
	ApiError    *SnykApiError
}

var (
	mutex = &sync.Mutex{}
)

func (f *FakeApiClient) addCall(params []any, op string) {
	mutex.Lock()
	defer mutex.Unlock()
	if f.Calls == nil {
		f.Calls = make(map[string][][]any)
	}
	calls := f.Calls[op]
	var opParams []any
	opParams = append(opParams, params...)

	f.Calls[op] = append(calls, opParams)
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
	f.Calls = map[string][][]any{}
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

func (f *FakeApiClient) SastEnabled() (sastEnabled bool, localCodeEngineEnabled bool, reportFalsePositivesEnabled bool, err *SnykApiError) {
	f.addCall([]any{}, SastEnabledOperation)
	return f.CodeEnabled, false, false, nil
}

func (f *FakeApiClient) GetActiveUser() (user ActiveUser, err *SnykApiError) {
	f.addCall([]any{}, ActiveUserOperation)

	if f.ApiError != nil {
		return ActiveUser{}, f.ApiError
	}

	return ActiveUser{Id: "FakeUser"}, nil
}
