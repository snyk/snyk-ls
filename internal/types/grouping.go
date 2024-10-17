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

package types

import "golang.org/x/mod/semver"

type Key string

type Groupable interface {
	GetGroupingKey() Key
	GetGroupingValue() any
	GetGroupingType() GroupingType
}

type Filterable interface {
	GetFilteringKey() Key
}

type GroupingFunction func(groupables []Groupable) any
type GroupingType string

const Quickfix GroupingType = "quickfix-grouping"

func MaxSemver() GroupingFunction {
	return func(groupables []Groupable) any {
		if len(groupables) == 0 {
			return nil
		}

		// find max semver version
		var chosenGroupable = groupables[0]
		for _, groupable := range groupables {
			if currentVersion, ok := groupable.GetGroupingValue().(string); ok {
				currentVersion = "v" + currentVersion
				if !semver.IsValid(currentVersion) {
					continue
				}

				if chosenGroupable == nil {
					chosenGroupable = groupable
				}

				group, ok := chosenGroupable.GetGroupingValue().(string)
				if !ok {
					continue
				}

				chosenVersion := "v" + group
				if semver.Compare(chosenVersion, currentVersion) < 0 {
					chosenGroupable = groupable
				}
			}
		}

		return chosenGroupable
	}
}
