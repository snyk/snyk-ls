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

func (f *Finder) Find(baseList, currentList []Identifiable) (enrichedList []Identifiable, err error) {
	deltaList, err := f.FindDiff(baseList, currentList)
	if err != nil {
		return nil, err
	}
	// Enrich IsNew property
	if f.enricher != nil {
		currentList = f.enricher.EnrichWithIsNew(currentList, deltaList)
	}

	return currentList, nil
}

func (f *Finder) FindDiff(baseList, currentList []Identifiable) (deltaList []Identifiable, err error) {
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
		f.enricher.EnrichWithId(baseList)
	}

	if f.matcher != nil {
		// Match ids from baseList to currentList if the issue is similar.
		currentList, err = f.matcher.Match(baseList, currentList)
		if err != nil {
			return nil, err
		}
		// Ensure new findings have ids
		if f.enricher != nil {
			f.enricher.EnrichWithId(currentList)
		}
	}

	deltaList = f.differ.Diff(baseList, currentList)

	return deltaList, nil
}
