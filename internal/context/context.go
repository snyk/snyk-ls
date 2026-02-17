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

// Package context implements context management for Snyk
package context

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/internal/types"
)

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

type dependenciesKeyType string

func (d dependenciesKeyType) String() string {
	return string(d)
}

var dependenciesKey dependenciesKeyType

const DepScanners = "scanners"
const DepNotifier = "notifier"
const DepScanNotifier = "scanNotifier"
const DepInstrumentor = "instrumentor"
const DepConfig = "config"
const DepInitializer = "initializer"
const DepApiClient = "snykApiClient"
const DepAuthService = "authService"
const DepScanPersister = "scanPersister"
const DepScanStateAggregator = "scanStateAggregator"
const DepStoredFolderConfig = "folderConfig"
const DepErrorReporter = "errorReporter"
const DepCLIExecutor = "cliExecutor"
const DepLearnService = "learnService"

// NewContextWithDependencies returns a new Context that carries dependencies.
// This can be used to pass pointers to injected (service) dependencies, e.g. a pointer
// to the learn service or the cli scanner.
//
// Returns:
//   - context.Context: the new enriched context
func NewContextWithDependencies(ctx context.Context, dependencies map[string]any) context.Context {
	return context.WithValue(ctx, dependenciesKey, dependencies)
}

// DependenciesFromContext returns the dependencies stored in ctx, if any.
// This can be used to retrieve pointers to injected (service) dependencies, e.g. a pointer
// to the learn service or the cli scanner.
//
// Returns:
//   - map[string]any: the dependencies stored in ctx
//   - bool: true if the dependencies were found, false otherwise
func DependenciesFromContext(ctx context.Context) (map[string]any, bool) {
	d, ok := ctx.Value(dependenciesKey).(map[string]any)
	return d, ok
}

type loggerKeyType string

func (l loggerKeyType) String() string {
	return string(l)
}

var loggerKey loggerKeyType

func NewContextWithLogger(ctx context.Context, logger *zerolog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

func LoggerFromContext(ctx context.Context) *zerolog.Logger {
	l := ctx.Value(loggerKey)
	if l == nil {
		l = log.Logger
	}
	returnLogger, ok := l.(*zerolog.Logger)
	if !ok {
		returnLogger = &log.Logger
	}
	return returnLogger
}

type filePathKeyType string
type workDirKeyType string

func (f filePathKeyType) String() string {
	return string(f)
}

func (w workDirKeyType) String() string {
	return string(w)
}

var filePathKey filePathKeyType
var workDirKey workDirKeyType

func NewContextWithWorkDirAndFilePath(ctx context.Context, workDir, filePath types.FilePath) context.Context {
	newCtx := context.WithValue(ctx, filePathKey, filePath)
	newCtx = context.WithValue(newCtx, workDirKey, workDir)
	return newCtx
}

func FilePathFromContext(ctx context.Context) types.FilePath {
	f, ok := ctx.Value(filePathKey).(types.FilePath)
	if !ok {
		return ""
	}
	return f
}

func WorkDirFromContext(ctx context.Context) types.FilePath {
	w, ok := ctx.Value(workDirKey).(types.FilePath)
	if !ok {
		return ""
	}
	return w
}

func Clone(ctx, newCtx context.Context) context.Context {
	deps, found := DependenciesFromContext(ctx)
	if !found {
		deps = map[string]any{}
	}
	newCtx = NewContextWithDependencies(newCtx, deps)
	newCtx = NewContextWithWorkDirAndFilePath(newCtx, WorkDirFromContext(ctx), FilePathFromContext(ctx))
	newCtx = NewContextWithLogger(newCtx, LoggerFromContext(ctx))
	dsScanType, found := DeltaScanTypeFromContext(ctx)
	if found {
		newCtx = NewContextWithDeltaScanType(newCtx, dsScanType)
	}

	scanSource, found := ScanSourceFromContext(ctx)
	if found {
		newCtx = NewContextWithScanSource(newCtx, scanSource)
	}
	return newCtx
}
