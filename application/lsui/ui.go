/*
 * © 2025 Snyk Limited
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

package lsui

import (
	"github.com/snyk/go-application-framework/pkg/ui"
)

type lsUI struct {
}

func NewLSUI() ui.UserInterface {
	return &lsUI{}
}

func (l *lsUI) Output(_ string) error {
	// No output support.
	return nil
}

func (l *lsUI) OutputError(_ error, _ ...ui.Opts) error {
	// No output support.
	return nil
}

func (l *lsUI) NewProgressBar(title string) ui.ProgressBar {
	return newLSProgressBar(title)
}

func (l *lsUI) Input(_ string) (string, error) {
	// No input support.
	panic("No input support for LS UI")
}
