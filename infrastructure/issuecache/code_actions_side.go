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

package issuecache

import (
	"sync"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

// codeActionsSide holds non-serializable CodeAction closures keyed by issue key
// (AdditionalData.GetKey). StorageBackend payloads strip CodeActions; readers
// merge from this map. Evicted only from ClearIssues / ClearIssuesByPath / Clear.
// UUID → key dispatch uses IssueIndex.KeyForActionUUID (cp11r.2).
type codeActionsSide struct {
	mu         sync.RWMutex
	byIssueKey map[string][]types.CodeAction
}

func newCodeActionsSide() *codeActionsSide {
	return &codeActionsSide{
		byIssueKey: make(map[string][]types.CodeAction),
	}
}

func (s *codeActionsSide) evictKey(key string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byIssueKey, key)
}

func (s *codeActionsSide) evictPath(index *IssueIndex, path types.FilePath) {
	keys := index.KeysForPath(path)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range keys {
		delete(s.byIssueKey, key)
	}
}

func (s *codeActionsSide) replaceFromIssue(issue types.Issue) {
	key := issueKey(issue)
	if key == "" {
		return
	}
	actions := issue.GetCodeActions()
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byIssueKey, key)
	if len(actions) == 0 {
		return
	}
	cp := make([]types.CodeAction, len(actions))
	copy(cp, actions)
	s.byIssueKey[key] = cp
}

func (s *codeActionsSide) actionsForKey(key string) ([]types.CodeAction, bool) {
	if key == "" {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.byIssueKey[key]
	return a, ok
}

func issueKey(issue types.Issue) string {
	if issue == nil {
		return ""
	}
	d := issue.GetAdditionalData()
	if d == nil {
		return ""
	}
	return d.GetKey()
}

// mergeCodeActionsCopy returns a new *snyk.Issue with CodeActions merged from the
// side map. Non-*snyk.Issue values are returned unchanged.
func (c *IssueCache) mergeCodeActionsCopy(issue types.Issue) types.Issue {
	si, ok := issue.(*snyk.Issue)
	if !ok {
		return issue
	}
	key := issueKey(issue)
	if key == "" {
		return issue
	}
	actions, ok := c.side.actionsForKey(key)
	if !ok || len(actions) == 0 {
		return issue
	}
	cl := si.Clone()
	cp := make([]types.CodeAction, len(actions))
	copy(cp, actions)
	cl.SetCodeActions(cp)
	return cl
}

func (c *IssueCache) materializeIssues(issues []types.Issue) []types.Issue {
	if len(issues) == 0 {
		return issues
	}
	out := make([]types.Issue, len(issues))
	for i := range issues {
		out[i] = c.mergeCodeActionsCopy(issues[i])
	}
	return out
}

// stripCodeActionsClone returns a copy of the issue with CodeActions cleared for storage.
func stripCodeActionsClone(issue types.Issue) types.Issue {
	si, ok := issue.(*snyk.Issue)
	if !ok {
		return issue
	}
	cl := si.Clone()
	cl.SetCodeActions(nil)
	return cl
}
