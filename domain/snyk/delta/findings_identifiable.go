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

import "github.com/snyk/snyk-ls/domain/snyk"

type FindingsFingerprintable interface {
	FindingsIdentifiable
	Fingerprint() string
}

type FingingsLocationable interface {
	FindingsIdentifiable
	// We should use snyk.Range type here. But since we will move it to GAF
	// We need to decide what we will do regarding this type in LS.
	GetLocation() snyk.Range
}

type FindingsPathable interface {
	FindingsIdentifiable
	Path() string
}

type FindingsIdentifiable interface {
	RuleId() string
	GlobalIdentity() string
	SetGlobalIdentity(globalIdentity string)
	SetIsNew(isNew bool)
	IsNew() bool
}