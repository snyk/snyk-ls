/*
 * © 2024-2026 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package oss

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestMemoOpenBrowserOSSDescriptionTitle_returnsSameStringForSameInputs(t *testing.T) {
	t.Cleanup(resetOSSCodeActionMemoCachesForTest)
	resetOSSCodeActionMemoCachesForTest()
	a := memoOpenBrowserOSSDescriptionTitle("XSS", "lodash")
	b := memoOpenBrowserOSSDescriptionTitle("XSS", "lodash")
	assert.Equal(t, a, b)
	assert.Contains(t, a, "XSS")
	assert.Contains(t, a, "lodash")
}

func TestAddSnykLearnAction_memoizesSuccessfulLessonLookup(t *testing.T) {
	t.Cleanup(resetOSSCodeActionMemoCachesForTest)
	resetOSSCodeActionMemoCachesForTest()
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	learnSvc := mock_learn.NewMockService(ctrl)
	learnSvc.EXPECT().
		GetLesson("npm", "SNYK-1", []string{"CWE-79"}, []string{"CVE-1"}, types.DependencyVulnerability).
		Return(&learn.Lesson{Url: "https://learn.example/lesson?loc=ide"}, nil).
		Times(1)

	ep := error_reporting.NewTestErrorReporter(engine)
	resolver := testutil.DefaultConfigResolver(engine)

	a := AddSnykLearnAction(engine, resolver, learnSvc, ep, "Bad vuln", "npm", "SNYK-1", []string{"CWE-79"}, []string{"CVE-1"}, nil)
	b := AddSnykLearnAction(engine, resolver, learnSvc, ep, "Bad vuln", "npm", "SNYK-1", []string{"CWE-79"}, []string{"CVE-1"}, nil)

	require.NotNil(t, a)
	require.NotNil(t, b)
	assert.Equal(t, a.GetTitle(), b.GetTitle())
	assert.NotSame(t, a, b, "each call must return a distinct action value so callers cannot mutate shared state")
}

func TestAddSnykLearnAction_cacheHit_rebuildsTitleFromCurrentVulnTitle(t *testing.T) {
	t.Cleanup(resetOSSCodeActionMemoCachesForTest)
	resetOSSCodeActionMemoCachesForTest()
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	learnSvc := mock_learn.NewMockService(ctrl)
	learnSvc.EXPECT().
		GetLesson("npm", "SNYK-1", []string{"CWE-79"}, []string{"CVE-1"}, types.DependencyVulnerability).
		Return(&learn.Lesson{Url: "https://learn.example/lesson?loc=ide"}, nil).
		Times(1)

	ep := error_reporting.NewTestErrorReporter(engine)
	resolver := testutil.DefaultConfigResolver(engine)

	first := AddSnykLearnAction(engine, resolver, learnSvc, ep, "Alpha title", "npm", "SNYK-1", []string{"CWE-79"}, []string{"CVE-1"}, nil)
	second := AddSnykLearnAction(engine, resolver, learnSvc, ep, "Beta title", "npm", "SNYK-1", []string{"CWE-79"}, []string{"CVE-1"}, nil)

	require.NotNil(t, first)
	require.NotNil(t, second)
	assert.Contains(t, first.GetTitle(), "Alpha title")
	assert.Contains(t, second.GetTitle(), "Beta title")
	assert.NotEqual(t, first.GetTitle(), second.GetTitle())
}

func TestAddSnykLearnAction_memoizesNegativeLessonLookup(t *testing.T) {
	t.Cleanup(resetOSSCodeActionMemoCachesForTest)
	resetOSSCodeActionMemoCachesForTest()
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	learnSvc := mock_learn.NewMockService(ctrl)
	learnSvc.EXPECT().
		GetLesson("npm", "SNYK-NONE", gomock.Any(), gomock.Any(), types.DependencyVulnerability).
		Return(nil, nil).
		Times(1)

	ep := error_reporting.NewTestErrorReporter(engine)
	resolver := testutil.DefaultConfigResolver(engine)

	assert.Nil(t, AddSnykLearnAction(engine, resolver, learnSvc, ep, "t", "npm", "SNYK-NONE", nil, nil, nil))
	assert.Nil(t, AddSnykLearnAction(engine, resolver, learnSvc, ep, "t", "npm", "SNYK-NONE", nil, nil, nil))
}
