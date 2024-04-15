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

package util

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

func GetIssueKey(ruleId string, path string, startLine int, endLine int, startCol int, endCol int) string {
	id := sha256.Sum256([]byte(ruleId + path + strconv.Itoa(startLine) + strconv.Itoa(endLine) + strconv.Itoa(startCol) + strconv.Itoa(endCol)))
	return hex.EncodeToString(id[:16])
}
