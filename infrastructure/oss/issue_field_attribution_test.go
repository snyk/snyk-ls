/*
 * © 2022-2026 Snyk Limited
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

package oss

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

type fieldAttributionStat struct {
	Name           string
	TotalBytes     int64
	NonEmptyCount  int
	MaxBytes       int64
	UniqueValues   int
	UniqueBytes    int64
	DedupSavingsMB float64
}

func applyFieldJSONToStat(stat *fieldAttributionStat, seen map[string]struct{}, fieldName string, f reflect.Value) {
	if !f.CanInterface() {
		return
	}
	b, err := json.Marshal(f.Interface())
	if err != nil {
		return
	}
	n := int64(len(b))
	if n <= 2 { // "" or null or {} or [] - treat as empty
		s := string(b)
		if s == "\"\"" || s == "null" || s == "{}" || s == "[]" || s == "0" || s == "false" {
			return
		}
	}
	stat.Name = fieldName
	stat.TotalBytes += n
	stat.NonEmptyCount++
	if n > stat.MaxBytes {
		stat.MaxBytes = n
	}
	if _, ok := seen[string(b)]; !ok {
		seen[string(b)] = struct{}{}
		stat.UniqueBytes += n
	}
}

func computeFieldAttributionStats(values []reflect.Value) []fieldAttributionStat {
	if len(values) == 0 {
		return nil
	}
	t0 := values[0].Type()
	numFields := t0.NumField()
	stats := make([]fieldAttributionStat, numFields)
	seen := make([]map[string]struct{}, numFields)
	for i := range seen {
		seen[i] = make(map[string]struct{})
	}
	for _, v := range values {
		for i := 0; i < numFields; i++ {
			applyFieldJSONToStat(&stats[i], seen[i], t0.Field(i).Name, v.Field(i))
		}
	}
	for i := range stats {
		stats[i].UniqueValues = len(seen[i])
		stats[i].DedupSavingsMB = float64(stats[i].TotalBytes-stats[i].UniqueBytes) / (1024 * 1024)
	}
	sort.SliceStable(stats, func(i, j int) bool {
		return stats[i].TotalBytes > stats[j].TotalBytes
	})
	return stats
}

// aggregateAndLogFieldStats builds per-field JSON size stats for a struct type and logs tables.
func aggregateAndLogFieldStats(t *testing.T, typeName string, values []reflect.Value) []fieldAttributionStat {
	t.Helper()
	stats := computeFieldAttributionStats(values)
	if len(stats) == 0 {
		return nil
	}
	t.Logf("=== %s (across %d values) ===", typeName, len(values))
	t.Logf("%-22s %12s %10s %10s %10s %14s",
		"field", "total_MB", "nonEmpty", "max_bytes", "unique", "dedup_save_MB")
	var grandTotal int64
	for _, s := range stats {
		if s.TotalBytes == 0 {
			continue
		}
		grandTotal += s.TotalBytes
		t.Logf("%-22s %12.2f %10d %10d %10d %14.2f",
			s.Name,
			float64(s.TotalBytes)/(1024*1024),
			s.NonEmptyCount, s.MaxBytes,
			s.UniqueValues, s.DedupSavingsMB)
	}
	t.Logf("TOTAL %s: %.2f MB", typeName, float64(grandTotal)/(1024*1024))
	return stats
}

// TestIssueFieldAttribution_FromRealCLIFixture measures per-field allocation size for
// snyk.Issue (top level) and the dominant snyk.OssIssueData payload it carries. Runs against
// the 3.8 MB testdata/nodejs-goof-legacy-example.json fixture (realistic large scan output)
// and prints two sorted tables:
//
//  1. snyk.Issue top-level fields — JSON byte length summed across all decoded issues.
//  2. snyk.OssIssueData fields     — same, but inside the AdditionalData payload.
//
// This is a diagnostic test used to justify IDE-1940 "future idea" vuln-scoped description
// dedup. It is skipped unless OSS_FIELD_ATTRIBUTION=1 so CI runs remain fast.
func TestIssueFieldAttribution_FromRealCLIFixture(t *testing.T) {
	if os.Getenv("OSS_FIELD_ATTRIBUTION") != "1" {
		t.Skip("set OSS_FIELD_ATTRIBUTION=1 to run field attribution diagnostic")
	}

	engine := testutil.UnitTest(t)

	raw, err := os.ReadFile("testdata/nodejs-goof-legacy-example.json")
	require.NoError(t, err)

	scanResults, err := UnmarshallOssJson(raw)
	require.NoError(t, err)
	require.NotEmpty(t, scanResults)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	learnService := mock_learn.NewMockService(ctrl)
	learnService.EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), types.DependencyVulnerability).
		Return(&learn.Lesson{Url: "https://learn.snyk.io/lesson/test"}, nil).
		AnyTimes()

	errorReporter := error_reporting.NewTestErrorReporter(engine)
	configResolver := testutil.DefaultConfigResolver(engine)
	workDir := types.FilePath("/tmp/goof")
	targetFilePath := types.FilePath("/tmp/goof/package.json")
	format := engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingFormat))

	var allIssues []types.Issue
	for _, sr := range scanResults {
		issues := convertScanResultToIssues(
			engine, configResolver, &sr, workDir, targetFilePath,
			[]byte(`{"dependencies":{}}`), learnService, errorReporter, format, nil,
		)
		allIssues = append(allIssues, issues...)
	}
	require.NotEmpty(t, allIssues)

	issueValues := make([]reflect.Value, 0, len(allIssues))
	ossValues := make([]reflect.Value, 0, len(allIssues))
	for _, i := range allIssues {
		si, ok := i.(*snyk.Issue)
		if !ok {
			continue
		}
		issueValues = append(issueValues, reflect.ValueOf(si).Elem())
		if ad, ok := si.AdditionalData.(snyk.OssIssueData); ok {
			ossValues = append(ossValues, reflect.ValueOf(&ad).Elem())
		}
	}

	_ = aggregateAndLogFieldStats(t, "snyk.Issue", issueValues)
	_ = aggregateAndLogFieldStats(t, "snyk.OssIssueData (AdditionalData)", ossValues)
}
