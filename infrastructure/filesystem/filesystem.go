/*
 * Copyright 2022 Snyk Ltd.
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

// This package defines basic interfaces to a file system.
package filesystem

import (
	"os"
	"strings"

	"github.com/pkg/errors"
)

type Filesystem struct{}

func New() *Filesystem {
	return &Filesystem{}
}

// GetLineOfCode returns the line of code from file (1-based)
func (f *Filesystem) GetLineOfCode(filePath string, line int) (string, error) {
	if line <= 0 {
		return "", errors.Errorf("invalid line number %d", line)
	}
	lines, err := f.readFile(filePath)
	if err != nil {
		return "", err
	}
	if len(lines) >= line {
		return lines[line-1], nil
	}
	return "", errors.Errorf("line number above number of lines")
}

func (f *Filesystem) readFile(filePath string) (lines []string, err error) {
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(bytes), "\n"), nil
}
