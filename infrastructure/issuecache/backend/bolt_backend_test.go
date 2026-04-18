/*
 * © 2026 Snyk Limited
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

package backend

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestBoltBackend_roundTrip(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenBoltDBForCacheDir(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = CloseBoltDBForTesting(dir) })

	b := NewBoltBackend(db, product.ProductCode)
	path := types.FilePath("/workspace/a.go")
	issues := []types.Issue{&snyk.Issue{
		ID:               "rule-1",
		AffectedFilePath: path,
		AdditionalData:   snyk.CodeIssueData{Key: "issue-key-1", Title: "t"},
	}}

	b.Set(path, issues)
	got, ok := b.Get(path)
	require.True(t, ok)
	require.Len(t, got, 1)
	assert.Equal(t, "issue-key-1", got[0].GetAdditionalData().GetKey())

	all := b.GetAll()
	require.Len(t, all, 1)
	assert.Len(t, all[path], 1)

	b.Remove(path)
	_, ok = b.Get(path)
	assert.False(t, ok)
}

func TestBoltBackend_separateProductBuckets(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenBoltDBForCacheDir(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = CloseBoltDBForTesting(dir) })

	bCode := NewBoltBackend(db, product.ProductCode)
	bSec := NewBoltBackend(db, product.ProductSecrets)
	path := types.FilePath("/x/a.go")
	bCode.Set(path, []types.Issue{&snyk.Issue{ID: "c", AffectedFilePath: path, AdditionalData: snyk.CodeIssueData{Key: "k1"}}})
	bSec.Set(path, []types.Issue{&snyk.Issue{ID: "s", AffectedFilePath: path, AdditionalData: snyk.CodeIssueData{Key: "k2"}}})

	gotCode, _ := bCode.Get(path)
	gotSec, _ := bSec.Get(path)
	require.Len(t, gotCode, 1)
	require.Len(t, gotSec, 1)
	assert.Equal(t, "k1", gotCode[0].GetAdditionalData().GetKey())
	assert.Equal(t, "k2", gotSec[0].GetAdditionalData().GetKey())
}
