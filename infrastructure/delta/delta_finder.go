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
	findingsEnricher Enricher
	matcher          Matcher
	differ           Differ
}

func (f *Finder) Init(e Enricher, m Matcher, d Differ) *Finder {
	return &Finder{
		findingsEnricher: e,
		matcher:          m,
		differ:           d,
	}
}

func (f *Finder) Find(baseList, currentList []Identifiable) (enrichedList, deltaList []Identifiable, err error) {
	if len(baseList) == 0 || len(currentList) == 0 {
		return nil, nil, errors.New("baselist or currentlist is empty")
	}

	if f.findingsEnricher != nil {
		f.findingsEnricher.EnrichWithId(baseList)
	}

	if f.matcher != nil {
		// Match ids from baseList to currentList if the issue is similar.
		currentList, err = f.matcher.Match(baseList, currentList)
		if err != nil {
			return nil, nil, err
		}
	}

	// Ensure new findings have ids
	if f.findingsEnricher != nil {
		f.findingsEnricher.EnrichWithId(currentList)
	}

	if f.differ == nil {
		return nil, nil, errors.New("findings differ not defined")
	}

	deltaList = f.differ.Diff(baseList, currentList)

	// Enrich IsNew property
	if f.findingsEnricher != nil {
		currentList = f.findingsEnricher.EnrichWithIsNew(currentList, deltaList)
	}

	return currentList, deltaList, nil
}
