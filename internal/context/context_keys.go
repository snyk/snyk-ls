/*
 * © 2025 Snyk Limited
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

package context

import "context"

type ScanSource string

func (s ScanSource) String() string {
	return string(s)
}

const (
	LLM ScanSource = "LLM"
	IDE ScanSource = "IDE"
)

type scanSourceKeyType int

var scanSourceKey scanSourceKeyType

func NewContextWithScanSource(ctx context.Context, source ScanSource) context.Context {
	return context.WithValue(ctx, scanSourceKey, source)
}

func ScanSourceFromContext(ctx context.Context) (ScanSource, bool) {
	s, ok := ctx.Value(scanSourceKey).(ScanSource)
	return s, ok
}

type DeltaScanType string

func (d DeltaScanType) String() string {
	return string(d)
}

type deltaScanTypeKeyType int

var deltaScanTypeKey deltaScanTypeKeyType

const (
	Reference        DeltaScanType = "Reference"
	WorkingDirectory DeltaScanType = "WorkingDirectory"
)

// NewContext returns a new Context that carries value u.
func NewContextWithDeltaScanType(ctx context.Context, dType DeltaScanType) context.Context {
	return context.WithValue(ctx, deltaScanTypeKey, dType)
}

// FromContext returns the User value stored in ctx, if any.
func DeltaScanTypeFromContext(ctx context.Context) (DeltaScanType, bool) {
	d, ok := ctx.Value(deltaScanTypeKey).(DeltaScanType)
	return d, ok
}
