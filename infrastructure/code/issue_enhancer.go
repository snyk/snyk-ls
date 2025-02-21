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

package code

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	codeClientObservability "github.com/snyk/code-client-go/observability"

	"github.com/snyk/snyk-ls/internal/types"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/util"
)

type IssueEnhancer struct {
	SnykCode      SnykCodeClient
	instrumentor  codeClientObservability.Instrumentor
	errorReporter codeClientObservability.ErrorReporter
	notifier      notification.Notifier
	learnService  learn.Service
	requestId     string
	rootPath      types.FilePath
	c             *config.Config
}

func newIssueEnhancer(SnykCode SnykCodeClient, instrumentor codeClientObservability.Instrumentor, errorReporter codeClientObservability.ErrorReporter, notifier notification.Notifier, learnService learn.Service, requestId string, rootPath types.FilePath, c *config.Config) IssueEnhancer {
	return IssueEnhancer{
		SnykCode:      SnykCode,
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		notifier:      notifier,
		learnService:  learnService,
		requestId:     requestId,
		rootPath:      rootPath,
		c:             c,
	}
}

// Adds code actions and code lenses for issues found
func (b *IssueEnhancer) addIssueActions(ctx context.Context, issues []types.Issue) {
	method := "addCodeActions"

	autoFixEnabled := getCodeSettings().isAutofixEnabled.Get()
	learnEnabled := b.c.IsSnykLearnCodeActionsEnabled()
	b.c.Logger().Debug().Str("method", method).Msg("Autofix is enabled: " + strconv.FormatBool(autoFixEnabled))
	b.c.Logger().Debug().Str("method", method).Msg("Snyk Learn is enabled: " + strconv.FormatBool(learnEnabled))

	if !autoFixEnabled && !learnEnabled {
		b.c.Logger().Trace().Msg("Autofix | Snyk Learn code actions are disabled, not adding code actions")
		return
	}

	for i := range issues {
		issueData, ok := issues[i].GetAdditionalData().(snyk.CodeIssueData)
		if !ok {
			b.c.Logger().Error().Str("method", method).Msg("Failed to fetch additional data")
			continue
		}

		issueData.HasAIFix = autoFixEnabled && issueData.IsAutofixable

		if issueData.HasAIFix && !issues[i].GetIsIgnored() {
			codeActionShowDocument := b.createShowDocumentCodeAction(issues[i])
			issues[i].SetCodeActions(append(issues[i].GetCodeActions(), codeActionShowDocument))

			uri, err := ideSnykURI(issues[i], "showInDetailsPanel")
			if err != nil {
				b.c.Logger().Error().Str("method", method).Msg("Failed to create URI for showInDetailPanel action")
				return
			}
			issues[i].SetCodelensCommands(append(issues[i].GetCodelensCommands(), types.CommandData{
				Title:     "⚡ Fix this issue: " + issueTitle(issues[i]),
				CommandId: types.NavigateToRangeCommand,
				Arguments: []any{uri, issues[i].GetRange()},
			}))
		}
		issues[i].SetAdditionalData(issueData)

		if learnEnabled {
			action := b.createOpenSnykLearnCodeAction(issues[i])
			if action != nil {
				issues[i].SetCodeActions(append(issues[i].GetCodeActions(), action))
			}
		}
	}
}

// returns the deferred code action CodeAction which calls autofix.
func (b *IssueEnhancer) createShowDocumentCodeAction(issue types.Issue) (codeAction types.CodeAction) {
	method := "code.createShowDocumentCodeAction"
	uri, err := ideSnykURI(issue, "showInDetailPanel")
	if err != nil {
		b.c.Logger().Error().Str("method", method).Msg("Failed to create URI for showInDetailPanel action")
		return nil
	}

	title := fmt.Sprintf("⚡ Fix this issue: %s (Snyk)", issueTitle(issue))

	codeAction = &snyk.CodeAction{
		Title: title,
		Command: &types.CommandData{
			Title:     title,
			CommandId: types.NavigateToRangeCommand,
			Arguments: []any{uri, issue.GetRange()},
		},
	}
	return codeAction
}

func (b *IssueEnhancer) autofixShowDetailsFunc(ctx context.Context, issue types.Issue) func() *types.CommandData {
	f := func() *types.CommandData {
		method := "code.autofixShowDetailsFunc"
		s := b.instrumentor.StartSpan(ctx, method)
		defer b.instrumentor.Finish(s)

		uri, err := ideSnykURI(issue, "showInDetailPanel")
		if err != nil {
			b.c.Logger().Error().Str("method", method).Msg("Failed to create URI for showInDetailPanel action")
			return nil
		}

		commandData := &types.CommandData{
			Title:     types.NavigateToRangeCommand,
			CommandId: types.NavigateToRangeCommand,
			Arguments: []any{uri, issue.GetRange()},
		}
		return commandData
	}
	return f
}

func (b *IssueEnhancer) createOpenSnykLearnCodeAction(issue types.Issue) (ca types.CodeAction) {
	title := fmt.Sprintf("Learn more about %s (Snyk)", issueTitle(issue))
	lesson, err := b.learnService.GetLesson(issue.GetEcosystem(), issue.GetID(), issue.GetCWEs(), issue.GetCVEs(), issue.GetIssueType())
	if err != nil {
		b.c.Logger().Err(err).Msg("failed to get lesson")
		b.errorReporter.CaptureError(err, codeClientObservability.ErrorReporterOptions{ErrorDiagnosticPath: ""})
		return nil
	}

	if lesson != nil && lesson.Url != "" {
		ca = &snyk.CodeAction{
			Title: title,
			Command: &types.CommandData{
				Title:     title,
				CommandId: types.OpenBrowserCommand,
				Arguments: []any{lesson.Url},
			},
		}
	}
	return ca
}

func getShardKey(folderPath types.FilePath, authToken string) string {
	if len(folderPath) > 0 {
		return util.Hash([]byte(folderPath))
	}
	if len(authToken) > 0 {
		return util.Hash([]byte(authToken))
	}

	return ""
}

func issueTitle(issue types.Issue) string {
	if issue.GetAdditionalData() == nil {
		return issue.GetID()
	}

	codeIssueData, ok := issue.GetAdditionalData().(snyk.CodeIssueData)
	if ok && codeIssueData.Title != "" {
		return codeIssueData.Title
	}

	return issue.GetID()
}

func issueId(issue types.Issue) string {
	if issue.GetAdditionalData() == nil {
		return issue.GetID()
	}

	codeIssueData, ok := issue.GetAdditionalData().(snyk.CodeIssueData)
	if ok && codeIssueData.GetKey() != "" {
		return codeIssueData.GetKey()
	}

	return issue.GetID()
}

func ideSnykURI(issue types.Issue, ideAction string) (string, error) {
	u := &url.URL{
		Scheme:   "snyk",
		Path:     string(issue.GetAffectedFilePath()),
		RawQuery: fmt.Sprintf("product=%s&issueId=%s&action=%s", url.QueryEscape(string(issue.GetProduct())), url.QueryEscape(issueId(issue)), ideAction),
	}

	return u.String(), nil
}
