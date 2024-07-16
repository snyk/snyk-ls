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
	"math"
	"strconv"
	"time"

	codeClientObservability "github.com/snyk/code-client-go/observability"
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
	b.c.Logger().Info().Str("method", method).Msg("Autofix is enabled: " + strconv.FormatBool(autoFixEnabled))
	b.c.Logger().Info().Str("method", method).Msg("Snyk Learn is enabled: " + strconv.FormatBool(learnEnabled))

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
			codeAction := *b.createDeferredAutofixCodeAction(ctx, issues[i], bundleHash)
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
func (b *IssueEnhancer) createDeferredAutofixCodeAction(ctx context.Context, issue snyk.Issue,
	bundleHash string) *snyk.CodeAction {
	autofixEditCallback := b.autofixFunc(ctx, issue, bundleHash)

	action, err := snyk.NewDeferredCodeAction("⚡ Fix this issue: "+issueTitle(issue)+" (Snyk)", &autofixEditCallback, nil, "", "")
	if err != nil {
		b.c.Logger().Error().Msg("failed to create deferred autofix code action")
		b.notifier.SendShowMessage(sglsp.MTError, "Something went wrong. Please contact Snyk support.")
		return nil
	}
	return &action
}

func (b *IssueEnhancer) autofixFunc(ctx context.Context, issue snyk.Issue,
	bundleHash string) func() *snyk.WorkspaceEdit {
	editFn := func() *snyk.WorkspaceEdit {
		c := config.CurrentConfig()
		method := "code.enhanceWithAutofixSuggestionEdits"
		s := b.instrumentor.StartSpan(ctx, method)
		defer b.instrumentor.Finish(s)

		p := progress.NewTracker(true)
		fixMsg := "Attempting to fix " + issueTitle(issue) + " (Snyk)"
		p.BeginWithMessage(fixMsg, "")
		defer p.End()
		b.notifier.SendShowMessage(sglsp.Info, fixMsg)

		encodedNormalizedPath, err := ToEncodedNormalizedPath(b.rootPath, issue.AffectedFilePath)
		if err != nil {
			c.Logger().
				Err(err).Str("method", method).
				Str("rootPath", b.rootPath).
				Str("AffectedFilePath", issue.AffectedFilePath).
				Msg("error converting to relative file path")
			b.notifier.SendShowMessage(sglsp.MTError, "Something went wrong. Please contact Snyk support.")
			return nil
		}

		autofixOptions := AutofixOptions{
			bundleHash: bundleHash,
			shardKey:   getShardKey(b.rootPath, c.Token()),
			filePath:   encodedNormalizedPath,
			issue:      issue,
		}

		// Polling function just calls the endpoint and registers result, signaling `done` to the
		// channel.
		pollFunc := func() (fix *AutofixSuggestion, complete bool) {
			b.c.Logger().Info().Msg("polling")
			fixSuggestions, fixStatus, err := b.SnykCode.GetAutofixSuggestions(s.Context(), autofixOptions, b.rootPath)
			fix = nil
			complete = false
			if err != nil {
				b.c.Logger().Error().
					Err(err).Str("method", method).Str("requestId", b.requestId).
					Str("stage", "requesting autofix").Msg("error requesting autofix")
				complete = true
			} else if fixStatus.message == completeStatus {
				if len(fixSuggestions) > 0 {
					// TODO(alex.gronskiy): currently, only the first ([0]) fix suggestion goes into the fix
					fix = &fixSuggestions[0]
				} else {
					b.c.Logger().Info().Str("method", method).Str("requestId", b.requestId).Msg("No good fix could be computed.")
				}
				complete = true
			}
			return fix, complete
		}

		// Actual polling loop.
		pollingTicker := time.NewTicker(1 * time.Second)
		defer pollingTicker.Stop()
		timeoutTimer := time.NewTimer(2 * time.Minute)
		defer timeoutTimer.Stop()
		tries := 1.0
		for {
			select {
			case <-timeoutTimer.C:
				b.c.Logger().Error().Str("method", "GetAutofixSuggestions").Str("requestId", b.requestId).Msg("timeout requesting autofix")
				b.notifier.SendShowMessage(sglsp.MTError, "Something went wrong. Please try again. Request ID: "+b.requestId)
				return nil
			case <-pollingTicker.C:
				p.ReportWithMessage(int(math.Min(tries, 99)), "Polling for fix...")
				fix, complete := pollFunc()
				if !complete {
					tries++
					continue
				}

				if fix == nil {
					b.notifier.SendShowMessage(sglsp.MTError, "Oh snap! 😔 The fix did not remediate the issue and was not applied.")
					return nil
				}

				// send feedback asynchronously, so people can actually see the changes done by the fix
				go func() {
					actionCommandMap, err := b.autofixFeedbackActions(fix.FixId)
					successMessage := "Congratulations! 🎉 You’ve just fixed this " + issueTitle(issue) + " issue."
					if err != nil {
						b.notifier.SendShowMessage(sglsp.Info, successMessage)
					} else {
						// sleep to give client side to actually apply & review the fix
						time.Sleep(2 * time.Second)
						b.notifier.Send(types.ShowMessageRequest{
							Message: successMessage + " Was this fix helpful?",
							Type:    types.Info,
							Actions: actionCommandMap,
						})
					}
				}()
				return &fix.AutofixEdit
			}
		}
	}

	return editFn
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
	createCommandData := func(positive bool) types.CommandData {
		return types.CommandData{
			Title:     types.CodeSubmitFixFeedback,
			CommandId: types.CodeSubmitFixFeedback,
			Arguments: []any{fixId, positive},
		}
	}
	actionCommandMap := data_structure.NewOrderedMap[types.MessageAction, types.CommandData]()
	positiveFeedbackCmd := createCommandData(true)
	negativeFeedbackCmd := createCommandData(false)

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
	if issue.AdditionalData != nil && issue.AdditionalData.(snyk.CodeIssueData).Title != "" {
		return issue.AdditionalData.(snyk.CodeIssueData).Title
	}

	return issue.ID
}
