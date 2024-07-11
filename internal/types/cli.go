/*
 * © 2024 Snyk Limited
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

package types

import "encoding/json"

type CliOutput struct {
	Code         int    `json:"code,omitempty"`
	ErrorMessage string `json:"error,omitempty"`
	Path         string `json:"path,omitempty"`
	Command      string `json:"command,omitempty"`
}

type CliError CliOutput

func (e CliError) Error() string {
	marshal, err := json.Marshal(e)
	if err != nil {
		return e.ErrorMessage
	}
	return string(marshal)
}
