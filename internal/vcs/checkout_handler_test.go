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

package vcs

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestCheckoutHandler_ShouldCheckout(t *testing.T) {
	c := testutil.UnitTest(t)
	repoPath := t.TempDir()
	_, _ = initGitRepo(t, repoPath, false)
	ch := NewCheckoutHandler(c.Engine().GetConfiguration())

	err := ch.CheckoutBaseBranch(c.Logger(), repoPath)

	assert.NotNil(t, ch.CleanupFunc())
	assert.NotNil(t, ch.Repo())
	assert.NotEmpty(t, ch.BaseFolderPath())

	ch.CleanupFunc()()
	assert.NoError(t, err)
}

func TestCheckoutHandler_InvalidGitRepo(t *testing.T) {
	c := testutil.UnitTest(t)
	repoPath := t.TempDir()
	ch := NewCheckoutHandler(c.Engine().GetConfiguration())

	err := ch.CheckoutBaseBranch(c.Logger(), repoPath)
	assert.Error(t, err)
	assert.Nil(t, ch.CleanupFunc())
	assert.Nil(t, ch.Repo())
	assert.Empty(t, ch.BaseFolderPath())
}

func TestCheckoutHandler_AlreadyCreated(t *testing.T) {
	c := testutil.UnitTest(t)
	repoPath := t.TempDir()
	_, _ = initGitRepo(t, repoPath, false)

	ch := NewCheckoutHandler(c.Engine().GetConfiguration())

	err := ch.CheckoutBaseBranch(c.Logger(), repoPath)
	assert.NoError(t, err)
	assert.NotNil(t, ch.CleanupFunc())
	assert.NotNil(t, ch.Repo())
	assert.NotEmpty(t, ch.BaseFolderPath())

	firstRunPath := ch.BaseFolderPath()
	firstRunRepo := ch.Repo()

	err = ch.CheckoutBaseBranch(c.Logger(), repoPath)
	assert.NoError(t, err)
	assert.NotNil(t, ch.CleanupFunc())
	assert.NotEmpty(t, ch.Repo())
	assert.NotEmpty(t, ch.BaseFolderPath())

	assert.Equal(t, firstRunRepo, ch.Repo())
	assert.Equal(t, firstRunPath, ch.BaseFolderPath())
	ch.CleanupFunc()()
}
