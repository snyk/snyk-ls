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
	identityEnricher IdentityEnricher
	matcher          FindingsMatcher
	differ           Differ
}

func (f *Finder) Init(ie IdentityEnricher, m FindingsMatcher, d Differ) *Finder {
	return &Finder{
		identityEnricher: ie,
		matcher:          m,
		differ:           d,
	}
}

func (f *Finder) Find(baseList, currentList []FindingsIdentifiable) ([]FindingsIdentifiable, error) {
	if len(baseList) == 0 || len(currentList) == 0 {
		return nil, errors.New("baselist or currentlist is empty")
	}

	if f.identityEnricher != nil {
		f.identityEnricher.EnrichWithId(baseList)
	}

	if f.matcher == nil {
		return nil, errors.New("findings matcher not defined")
	}

	// Match ids from baseList to currentList if the issue is similar.
	err := f.matcher.Match(baseList, currentList)
	if err != nil {
		return nil, err
	}

	// Ensure new findings have ids
	if f.identityEnricher != nil {
		f.identityEnricher.EnrichWithId(currentList)
	}

	if f.differ == nil {
		return nil, errors.New("findings differ not defined")
	}

	delta := f.differ.Diff(baseList, currentList)

	return delta, nil
}
