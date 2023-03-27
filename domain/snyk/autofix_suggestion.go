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

package snyk

// AutofixSuggestion models a fix returned by autofix service
type AutofixSuggestion struct {
	// CodeAction can contain workspace edits or commands to be executed.
	// TODO(alex.gronskiy): currently we return full file fixed code and edits contain thus "full
	// file replace".
	// This is a known point of improvement which is easy to implement but will be
	// done later on re-iteration.
	AutofixEdit WorkspaceEdit
}