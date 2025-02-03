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

// This package defines basic interfaces to a file system.
package filesystem

import (
	"bufio"
	"os"

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

	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	currentLine := 0
	for scanner.Scan() {
		currentLine++
		if currentLine == line {
			return scanner.Text(), nil
		}
	}

	if err = scanner.Err(); err != nil {
		return "", err
	}

	return "", errors.Errorf("line number above number of lines")
}
