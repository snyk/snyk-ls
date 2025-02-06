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
	codeClientObservability "github.com/snyk/code-client-go/observability"
	"strconv"

	"github.com/snyk/snyk-ls/internal/types"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/data_structure"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/util"
)

type IssueEnhancer struct {
	SnykCode      SnykCodeClient
	instrumentor  codeClientObservability.Instrumentor
	errorReporter codeClientObservability.ErrorReporter
	notifier      notification.Notifier
	learnService  learn.Service
	requestId     string
	rootPath      string
	c             *config.Config
}

func newIssueEnhancer(
	SnykCode SnykCodeClient,
	instrumentor codeClientObservability.Instrumentor,
	errorReporter codeClientObservability.ErrorReporter,
	notifier notification.Notifier,
	learnService learn.Service,
	requestId string,
	rootPath string,
	c *config.Config,
) IssueEnhancer {
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
func (b *IssueEnhancer) addIssueActions(ctx context.Context, issues []snyk.Issue, bundleHash string) {
	method := "addCodeActions"

	autoFixEnabled := getCodeSettings().isAutofixEnabled.Get()
	learnEnabled := config.CurrentConfig().IsSnykLearnCodeActionsEnabled()
	b.c.Logger().Debug().Str("method", method).Msg("Autofix is enabled: " + strconv.FormatBool(autoFixEnabled))
	b.c.Logger().Debug().Str("method", method).Msg("Snyk Learn is enabled: " + strconv.FormatBool(learnEnabled))

	if !autoFixEnabled && !learnEnabled {
		b.c.Logger().Trace().Msg("Autofix | Snyk Learn code actions are disabled, not adding code actions")
		return
	}

	for i := range issues {
		issueData, ok := issues[i].AdditionalData.(snyk.CodeIssueData)
		if !ok {
			b.c.Logger().Error().Str("method", method).Msg("Failed to fetch additional data")
			continue
		}

		issueData.HasAIFix = autoFixEnabled && issueData.IsAutofixable

		if issueData.HasAIFix && !issues[i].IsIgnored {
			codeAction := *b.createDeferredAutofixCodeAction(ctx, issues[i])
			issues[i].CodeActions = append(issues[i].CodeActions, codeAction)

			codeActionId := *codeAction.Uuid
			issues[i].CodelensCommands = append(issues[i].CodelensCommands, types.CommandData{
				Title:     "⚡ Fix this issue: " + issueTitle(issues[i]),
				CommandId: types.CodeFixCommand,
				Arguments: []any{
					codeActionId,
					issues[i].AffectedFilePath,
					issues[i].Range,
				},
			})
		}
		issues[i].AdditionalData = issueData

		if learnEnabled {
			action := b.createOpenSnykLearnCodeAction(issues[i])
			if action != nil {
				issues[i].CodeActions = append(issues[i].CodeActions, *action)
			}
		}
	}
}

// returns the deferred code action CodeAction which calls autofix.
func (b *IssueEnhancer) createDeferredAutofixCodeAction(ctx context.Context, issue snyk.Issue) *snyk.CodeAction {
	autofixEditCallback := b.autofixFunc(ctx, issue)

	action, err := snyk.NewDeferredCodeAction("⚡ Fix this issue: "+issueTitle(issue)+" (Snyk)", &autofixEditCallback, nil, "", "")
	if err != nil {
		b.c.Logger().Error().Msg("failed to create deferred autofix code action")
		b.notifier.SendShowMessage(sglsp.MTError, "Something went wrong. Please contact Snyk support.")
		return nil
	}
	return &action
}

func (b *IssueEnhancer) autofixFunc(ctx context.Context, issue snyk.Issue) func() *snyk.WorkspaceEdit {
	editFn := func() *snyk.WorkspaceEdit {
		method := "code.enhanceWithAutofixSuggestionEdits"
		s := b.instrumentor.StartSpan(ctx, method)
		defer b.instrumentor.Finish(s)
		ctx, cancel := context.WithCancel(s.Context())
		defer cancel()

		p := progress.NewTracker(true)
		go func() { p.CancelOrDone(cancel, ctx.Done()) }() // make uploads in batches until no missing files reported anymore
		fixMsg := "Opening Details panel for issue " + issueTitle(issue) + " (Snyk)"
		p.BeginWithMessage(fixMsg, "")
		defer p.End()
		b.notifier.SendShowMessage(sglsp.Info, fixMsg)
		b.sendDetailsPanelNotification(issue)
		//js for triggering the button, here or in ide?

		return nil
	}
	return editFn
}

func (b *IssueEnhancer) sendDetailsPanelNotification(issue snyk.Issue) {
	method := "sendDetailsPanelNotification"
	htmlRender, err := NewHtmlRenderer(b.c)
	if err != nil {
		b.c.Logger().Debug().Str("method", method).Msg("Cannot create Details HTML render")
		return
	}
	issueDetailsParams := types.IssueDetails{IssueDetails: htmlRender.GetDetailsHtml(issue)}
	b.notifier.Send(issueDetailsParams)
}

func ToEncodedNormalizedPath(rootPath string, filePath string) (string, error) {
	relativePath, err := ToRelativeUnixPath(rootPath, filePath)
	if err != nil {
		// couldn't make it relative, so it's already relative
		relativePath = filePath
	}

	encodedRelativePath := EncodePath(relativePath)
	return encodedRelativePath, nil
}

func (b *IssueEnhancer) autofixFeedbackActions(fixId string) (*data_structure.OrderedMap[types.MessageAction, types.CommandData], error) {
	createCommandData := func(feedback string) types.CommandData {
		return types.CommandData{
			Title:     types.CodeSubmitFixFeedback,
			CommandId: types.CodeSubmitFixFeedback,
			Arguments: []any{fixId, feedback},
		}
	}
	actionCommandMap := data_structure.NewOrderedMap[types.MessageAction, types.CommandData]()
	positiveFeedbackCmd := createCommandData(FixPositiveFeedback)
	negativeFeedbackCmd := createCommandData(FixNegativeFeedback)

	actionCommandMap.Add("👍", positiveFeedbackCmd)
	actionCommandMap.Add("👎", negativeFeedbackCmd)

	return actionCommandMap, nil
}

func (b *IssueEnhancer) createOpenSnykLearnCodeAction(issue snyk.Issue) (ca *snyk.CodeAction) {
	title := fmt.Sprintf("Learn more about %s (Snyk)", issueTitle(issue))
	lesson, err := b.learnService.GetLesson(issue.Ecosystem, issue.ID, issue.CWEs, issue.CVEs, issue.IssueType)
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

func getShardKey(folderPath string, authToken string) string {
	if len(folderPath) > 0 {
		return util.Hash([]byte(folderPath))
	}
	if len(authToken) > 0 {
		return util.Hash([]byte(authToken))
	}

	return ""
}

func issueTitle(issue snyk.Issue) string {
	if issue.AdditionalData == nil {
		return issue.ID
	}

	codeIssueData, ok := issue.AdditionalData.(snyk.CodeIssueData)
	if ok && codeIssueData.Title != "" {
		return codeIssueData.Title
	}

	return issue.ID
}
