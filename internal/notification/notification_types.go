/*
 * © 2023 Snyk Limited
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

package notification

import "github.com/snyk/snyk-ls/domain/snyk"

type MessageAction string

type Type int

const (
	Error   Type = 1
	Warning Type = 2
	Info    Type = 3
)

type ShowMessageRequest struct {
	Message string                         `json:"message"`
	Type    Type                           `json:"type"`
	Actions map[MessageAction]snyk.Command `json:"actions"`
}
