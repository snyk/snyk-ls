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

package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_DiagnosticsOverview(t *testing.T) {
	t.Run("sends notification", func(t *testing.T) {
		c := testutil.UnitTest(t)
		issuesByFile := snyk.IssuesByFile{}
		notifier := notification.NewNotifier()
		notificationChannel := make(chan bool)
		callback := func(params any) {
			switch params.(type) {
			case types.DiagnosticsOverviewParams:
				notificationChannel <- true
			}
		}
		notifier.CreateListener(callback)

		SendDiagnosticsOverview(c, product.ProductOpenSource, issuesByFile, notifier)

		require.Eventually(t, func() bool {
			<-notificationChannel
			return true
		}, time.Second*5, time.Millisecond)
	})

	t.Run("adds trees with div for each file name", func(t *testing.T) {
		c := testutil.UnitTest(t)
		issuesByFile := snyk.IssuesByFile{}
		expectedTitle := "Fixable Great Title!"
		issuesByFile["file1"] = getTestIssues(t, true, expectedTitle)

		notifier := notification.NewNotifier()
		notificationChannel := make(chan bool)
		callback := func(params any) {
			switch p := params.(type) {
			case types.DiagnosticsOverviewParams:
				require.Equal(t, product.ProductOpenSource.ToProductCodename(), p.Product)
				require.Contains(t, p.Html, "1 unique issue: 1 critical")
				require.Contains(t, p.Html, fmt.Sprintf("%s", expectedTitle))
				os.WriteFile(filepath.Base(t.Name()+".html"), []byte(p.Html), 0644)
				notificationChannel <- true
			}
		}
		notifier.CreateListener(callback)

		SendDiagnosticsOverview(c, product.ProductOpenSource, issuesByFile, notifier)

		require.Eventually(t, func() bool {
			<-notificationChannel
			return true
		}, time.Second*5, time.Millisecond)
	})
}

type mockAddData struct {
	isFixable bool
	key       string
	title     string
}

func (m mockAddData) GetKey() string {
	return m.key
}

func (m mockAddData) GetTitle() string {
	return m.title
}

func (m mockAddData) IsFixable() bool {
	return m.isFixable
}

func getTestIssues(t *testing.T, isFixable bool, title string) []snyk.Issue {
	t.Helper()
	return []snyk.Issue{
		{
			ID:       "id1",
			Severity: snyk.Critical,
			Message:  "message1",
			AdditionalData: mockAddData{
				title:     title,
				key:       uuid.NewString(),
				isFixable: isFixable},
		}}
}
