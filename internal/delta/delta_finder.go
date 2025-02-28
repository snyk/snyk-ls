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

package delta

import (
	"errors"
)

type Finder struct {
	enricher Enricher
	matcher  Matcher
	differ   Differ
}

func NewFinder(options ...func(*Finder)) *Finder {
	f := &Finder{}
	for _, option := range options {
		option(f)
	}
	return f
}

func WithEnricher(enricher Enricher) func(*Finder) {
	return func(f *Finder) {
		f.enricher = enricher
	}
}

func WithMatcher(matcher Matcher) func(*Finder) {
	return func(f *Finder) {
		f.matcher = matcher
	}
}

func WithDiffer(differ Differ) func(*Finder) {
	return func(f *Finder) {
		f.differ = differ
	}
}

func (f *Finder) DiffAndEnrich(baseList, allIssues []Identifiable) ([]Identifiable, error) {
	newIssueList, err := f.Diff(baseList, allIssues)
	if err != nil {
		return nil, err
	}

	if f.enricher != nil {
		allIssues = f.enricher.EnrichWithIsNew(allIssues, newIssueList)
	}

	return allIssues, nil
}

func (f *Finder) Diff(baseList, currentList []Identifiable) (diffList []Identifiable, err error) {
	if len(currentList) == 0 {
		return nil, errors.New("currentlist is empty")
	}

	if len(baseList) == 0 {
		return currentList, nil
	}

	if f.differ == nil {
		return nil, errors.New("findings differ not defined")
	}

	if f.enricher != nil {
		baseList = f.enricher.EnrichWithId(baseList)
	}

	if f.matcher != nil {
		// Match ids from baseList to currentList if the issue is similar
		// Set the GlobalIdentifier to the matched issue's global identifier
		currentList, err = f.matcher.Match(baseList, currentList)
		if err != nil {
			return nil, err
		}

		// Ensure new findings have ids, if there's no match
		if f.enricher != nil {
			currentList = f.enricher.EnrichWithId(currentList)
		}
	}

	diffList = f.differ.Diff(baseList, currentList)

	return diffList, nil
}
