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

package storedconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func SetupCustomTestRepo(t *testing.T, rootDir types.FilePath, url string, targetCommit string, logger *zerolog.Logger) (types.FilePath, error) {
	t.Helper()
	tempDir := filepath.Join(string(rootDir), util.Sha256First16Hash(t.Name()))
	assert.NoError(t, os.MkdirAll(tempDir, 0755))
	repoDir := "1"
	absoluteCloneRepoDir := filepath.Join(tempDir, repoDir)
	cmd := []string{"clone", "-v", url, repoDir}
	logger.Debug().Interface("cmd", cmd).Msg("clone command")
	clone := exec.Command("git", cmd...)
	clone.Dir = tempDir
	reset := exec.Command("git", "reset", "--hard", targetCommit)
	reset.Dir = absoluteCloneRepoDir

	clean := exec.Command("git", "clean", "--force")
	clean.Dir = absoluteCloneRepoDir

	output, err := clone.CombinedOutput()
	if err != nil {
		t.Fatal(err, "clone didn't work")
	}

	logger.Debug().Msg(string(output))
	output, _ = reset.CombinedOutput()

	logger.Debug().Msg(string(output))
	output, err = clean.CombinedOutput()

	logger.Debug().Msg(string(output))
	return types.FilePath(absoluteCloneRepoDir), err
}
