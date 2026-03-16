/*
 * © 2023 Snyk Limited All rights reserved.
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

// Package ls_extension implements the language server extension for integration with GAF
package ls_extension

import (
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Init registers all workflows provided by the language server extension.
// This includes the language server itself and diagnostic tools.
func Init(engine workflow.Engine) error {
	if err := initLanguageServer(engine); err != nil {
		return err
	}
	if err := initToolsIDEDirectoryCheck(engine); err != nil {
		return err
	}
	return nil
}
