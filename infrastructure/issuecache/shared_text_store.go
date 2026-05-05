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
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

type sharedTextEntry struct {
	text     string
	refCount int
}

type sharedTextStore struct {
	mu           sync.RWMutex
	entries      map[string]*sharedTextEntry
	refsByIssue  map[string]map[string]struct{}
	issuesByPath map[types.FilePath]map[string]struct{}
}

func newSharedTextStore() *sharedTextStore {
	return &sharedTextStore{
		entries:      map[string]*sharedTextEntry{},
		refsByIssue:  map[string]map[string]struct{}{},
		issuesByPath: map[types.FilePath]map[string]struct{}{},
	}
}

func (s *sharedTextStore) internIssue(issue types.Issue) types.Issue {
	si, ok := issue.(*snyk.Issue)
	if !ok {
		return issue
	}
	key := issueKey(si)
	if key == "" {
		return issue
	}

	cl := si.Clone()
	path := cl.GetAffectedFilePath()
	p := cl.GetProduct()
	cl.Message = s.intern(path, key, p, "issue.message", cl.Message)
	cl.FormattedMessage = s.intern(path, key, p, "issue.formattedMessage", cl.FormattedMessage)
	cl.References = s.internReferences(path, key, p, "issue.references", cl.References)

	switch ad := cl.AdditionalData.(type) {
	case snyk.OssIssueData:
		ad.Description = s.intern(path, key, p, "oss.description", ad.Description)
		ad.Details = s.intern(path, key, p, "oss.details", ad.Details)
		ad.Remediation = s.intern(path, key, p, "oss.remediation", ad.Remediation)
		ad.References = s.internReferences(path, key, p, "oss.references", ad.References)
		ad.CvssSources = s.internCvssSources(path, key, p, "oss.cvssSources", ad.CvssSources)
		cl.AdditionalData = ad
	case snyk.IaCIssueData:
		ad.Issue = s.intern(path, key, p, "iac.issue", ad.Issue)
		ad.Impact = s.intern(path, key, p, "iac.impact", ad.Impact)
		ad.Resolve = s.intern(path, key, p, "iac.resolve", ad.Resolve)
		ad.References = s.internStringSlice(path, key, p, "iac.references", ad.References)
		cl.AdditionalData = ad
	}

	return cl
}

func (s *sharedTextStore) hydrateIssue(issue types.Issue) types.Issue {
	si, ok := issue.(*snyk.Issue)
	if !ok {
		return issue
	}
	p := si.GetProduct()
	si.Message = s.canonical(p, "issue.message", si.Message)
	si.FormattedMessage = s.canonical(p, "issue.formattedMessage", si.FormattedMessage)
	si.References = s.canonicalReferences(p, "issue.references", si.References)

	switch ad := si.AdditionalData.(type) {
	case snyk.OssIssueData:
		ad.Description = s.canonical(p, "oss.description", ad.Description)
		ad.Details = s.canonical(p, "oss.details", ad.Details)
		ad.Remediation = s.canonical(p, "oss.remediation", ad.Remediation)
		ad.References = s.canonicalReferences(p, "oss.references", ad.References)
		ad.CvssSources = s.canonicalCvssSources(p, "oss.cvssSources", ad.CvssSources)
		si.AdditionalData = ad
	case snyk.IaCIssueData:
		ad.Issue = s.canonical(p, "iac.issue", ad.Issue)
		ad.Impact = s.canonical(p, "iac.impact", ad.Impact)
		ad.Resolve = s.canonical(p, "iac.resolve", ad.Resolve)
		ad.References = s.canonicalStringSlice(p, "iac.references", ad.References)
		si.AdditionalData = ad
	}

	return si
}

func (s *sharedTextStore) releasePath(path types.FilePath) {
	s.mu.Lock()
	defer s.mu.Unlock()

	issueKeys := s.issuesByPath[path]
	for issueKey := range issueKeys {
		s.releaseIssueLocked(issueKey)
	}
	delete(s.issuesByPath, path)
}

func (s *sharedTextStore) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func (s *sharedTextStore) intern(path types.FilePath, issueKey string, p product.Product, field string, text string) string {
	if text == "" {
		return ""
	}
	entryID := sharedTextID(p, field, text)
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[entryID]
	if !ok {
		entry = &sharedTextEntry{text: text}
		s.entries[entryID] = entry
	}
	if _, ok := s.refsByIssue[issueKey]; !ok {
		s.refsByIssue[issueKey] = map[string]struct{}{}
	}
	if _, ok := s.refsByIssue[issueKey][entryID]; !ok {
		s.refsByIssue[issueKey][entryID] = struct{}{}
		entry.refCount++
	}
	if _, ok := s.issuesByPath[path]; !ok {
		s.issuesByPath[path] = map[string]struct{}{}
	}
	s.issuesByPath[path][issueKey] = struct{}{}
	return entry.text
}

func (s *sharedTextStore) canonical(p product.Product, field string, text string) string {
	if text == "" {
		return ""
	}
	entryID := sharedTextID(p, field, text)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if entry, ok := s.entries[entryID]; ok {
		return entry.text
	}
	return text
}

func (s *sharedTextStore) releaseIssueLocked(issueKey string) {
	entryIDs := s.refsByIssue[issueKey]
	for entryID := range entryIDs {
		entry := s.entries[entryID]
		if entry == nil {
			continue
		}
		entry.refCount--
		if entry.refCount <= 0 {
			delete(s.entries, entryID)
		}
	}
	delete(s.refsByIssue, issueKey)
}

func (s *sharedTextStore) internReferences(path types.FilePath, issueKey string, p product.Product, field string, refs []types.Reference) []types.Reference {
	if len(refs) == 0 {
		return refs
	}
	out := make([]types.Reference, len(refs))
	for i, ref := range refs {
		out[i] = ref
		out[i].Title = s.intern(path, issueKey, p, field+".title", ref.Title)
	}
	return out
}

func (s *sharedTextStore) canonicalReferences(p product.Product, field string, refs []types.Reference) []types.Reference {
	if len(refs) == 0 {
		return refs
	}
	out := make([]types.Reference, len(refs))
	for i, ref := range refs {
		out[i] = ref
		out[i].Title = s.canonical(p, field+".title", ref.Title)
	}
	return out
}

func (s *sharedTextStore) internStringSlice(path types.FilePath, issueKey string, p product.Product, field string, values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = s.intern(path, issueKey, p, field, value)
	}
	return out
}

func (s *sharedTextStore) canonicalStringSlice(p product.Product, field string, values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = s.canonical(p, field, value)
	}
	return out
}

func (s *sharedTextStore) internCvssSources(path types.FilePath, issueKey string, p product.Product, field string, sources []types.CvssSource) []types.CvssSource {
	if len(sources) == 0 {
		return sources
	}
	out := make([]types.CvssSource, len(sources))
	for i, source := range sources {
		out[i] = source
		out[i].Type = s.intern(path, issueKey, p, field+".type", source.Type)
		out[i].Vector = s.intern(path, issueKey, p, field+".vector", source.Vector)
		out[i].Assigner = s.intern(path, issueKey, p, field+".assigner", source.Assigner)
		out[i].Severity = s.intern(path, issueKey, p, field+".severity", source.Severity)
		out[i].CvssVersion = s.intern(path, issueKey, p, field+".cvssVersion", source.CvssVersion)
		out[i].ModificationTime = s.intern(path, issueKey, p, field+".modificationTime", source.ModificationTime)
	}
	return out
}

func (s *sharedTextStore) canonicalCvssSources(p product.Product, field string, sources []types.CvssSource) []types.CvssSource {
	if len(sources) == 0 {
		return sources
	}
	out := make([]types.CvssSource, len(sources))
	for i, source := range sources {
		out[i] = source
		out[i].Type = s.canonical(p, field+".type", source.Type)
		out[i].Vector = s.canonical(p, field+".vector", source.Vector)
		out[i].Assigner = s.canonical(p, field+".assigner", source.Assigner)
		out[i].Severity = s.canonical(p, field+".severity", source.Severity)
		out[i].CvssVersion = s.canonical(p, field+".cvssVersion", source.CvssVersion)
		out[i].ModificationTime = s.canonical(p, field+".modificationTime", source.ModificationTime)
	}
	return out
}

func sharedTextID(p product.Product, field string, text string) string {
	var b strings.Builder
	b.WriteString(string(p))
	b.WriteByte(0)
	b.WriteString(field)
	b.WriteByte(0)
	b.WriteString(text)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
