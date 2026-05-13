/*
 * © 2026 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

// ABOUTME: Generates HTML fixture files for the issue-detail and scan-summary panels.
// ABOUTME: Pick a panel with --panel and write the result with --output-file.
// ABOUTME: Used by js-tests Playwright screenshot baselines.
// ABOUTME: Run with: go run scripts/panel-fixtures/main.go --panel oss-suggestion --output-file out.html
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/iac"
	"github.com/snyk/snyk-ls/infrastructure/oss"
	"github.com/snyk/snyk-ls/infrastructure/secrets"
	"github.com/snyk/snyk-ls/internal/types"
)

func main() {
	panel := flag.String("panel", "", "panel to render: code-suggestion|oss-suggestion|iac-suggestion|secrets-suggestion|scan-summary")
	outputFile := flag.String("output-file", "", "write HTML to file (otherwise stdout)")
	flag.Parse()

	engine, _ := config.InitEngine(nil)
	logger := engine.GetLogger()

	var html string
	var err error
	switch *panel {
	case "code-suggestion":
		html, err = renderCode(engine)
	case "oss-suggestion":
		html, err = renderOSS(engine)
	case "iac-suggestion":
		html, err = renderIaC(engine, logger)
	case "secrets-suggestion":
		html, err = renderSecrets(engine)
	case "scan-summary":
		html, err = renderSummary(engine, logger)
	default:
		fmt.Fprintf(os.Stderr, "unknown panel %q (use code-suggestion|oss-suggestion|iac-suggestion|secrets-suggestion|scan-summary)\n", *panel)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "render %s: %v\n", *panel, err)
		os.Exit(1)
	}

	html = replaceIDEPlaceholders(html)

	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, []byte(html), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", *outputFile, err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stdout, html)
}

func renderCode(engine workflow.Engine) (string, error) {
	r, err := code.GetHTMLRenderer(engine, featureflag.NewFakeService())
	if err != nil {
		return "", err
	}
	return r.GetDetailsHtml(exampleCodeIssue()), nil
}

func renderOSS(engine workflow.Engine) (string, error) {
	r, err := oss.NewHtmlRenderer(engine)
	if err != nil {
		return "", err
	}
	return r.GetDetailsHtml(exampleOSSIssue()), nil
}

func renderIaC(engine workflow.Engine, logger *zerolog.Logger) (string, error) {
	r, err := iac.NewHtmlRenderer(engine.GetConfiguration(), logger)
	if err != nil {
		return "", err
	}
	return r.GetDetailsHtml(exampleIaCIssue()), nil
}

func renderSecrets(engine workflow.Engine) (string, error) {
	r, err := secrets.NewHtmlRenderer(engine, featureflag.NewFakeService())
	if err != nil {
		return "", err
	}
	return r.GetDetailsHtml(exampleSecretsIssue()), nil
}

func renderSummary(engine workflow.Engine, logger *zerolog.Logger) (string, error) {
	r, err := scanstates.NewHtmlRenderer(engine.GetConfiguration(), logger, engine, types.NewConfigResolver(logger))
	if err != nil {
		return "", err
	}
	return r.GetSummaryHtml(scanstates.StateSnapshot{}), nil
}

func exampleCodeIssue() *snyk.Issue {
	return &snyk.Issue{
		ID:        "go/HardcodedCredentials/test",
		Severity:  types.High,
		CWEs:      []string{"CWE-798"},
		LessonUrl: "https://learn.snyk.io/lesson/hardcoded-credentials/?loc=ide",
		Range: types.Range{
			Start: types.Position{Line: 41, Character: 4},
			End:   types.Position{Line: 41, Character: 32},
		},
		AdditionalData: snyk.CodeIssueData{
			Title:           "Use of Hardcoded Credentials",
			IsSecurityType:  true,
			Text:            "Hardcoded credentials let attackers who read the source obtain valid authentication material. Use a secrets manager or environment variables instead.",
			RepoDatasetSize: 1234,
			PriorityScore:   850,
			HasAIFix:        true,
			DataFlow: []snyk.DataFlowElement{
				{
					Position: 0,
					FilePath: "/workspace/main.go",
					FlowRange: types.Range{
						Start: types.Position{Line: 41, Character: 4},
						End:   types.Position{Line: 41, Character: 32},
					},
					Content: `password := "hunter2"`,
				},
				{
					Position: 1,
					FilePath: "/workspace/auth/login.go",
					FlowRange: types.Range{
						Start: types.Position{Line: 12, Character: 8},
						End:   types.Position{Line: 12, Character: 28},
					},
					Content: `db.Connect(user, password)`,
				},
			},
			ExampleCommitFixes: []snyk.ExampleCommitFix{
				{
					CommitURL: "https://github.com/example/repo/commit/abcdef1",
					Lines: []snyk.CommitChangeLine{
						{LineNumber: 41, LineChange: "removed", Line: `password := "hunter2"`},
						{LineNumber: 41, LineChange: "added", Line: `password := os.Getenv("DB_PASSWORD")`},
					},
				},
			},
		},
	}
}

func exampleOSSIssue() *snyk.Issue {
	data := snyk.OssIssueData{
		Title:       "Prototype Pollution",
		Name:        "lodash",
		Description: "- Lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution\n- An attacker can add or modify object properties on the prototype",
		From:        []string{"my-app@1.0.0", "express@4.17.1", "lodash@4.17.15"},
		Lesson:      "https://learn.snyk.io/lesson/prototype-pollution/?loc=ide",
	}
	data.MatchingIssues = append(data.MatchingIssues, data)
	return &snyk.Issue{
		ID:             "SNYK-JS-LODASH-590103",
		Severity:       types.High,
		AdditionalData: data,
	}
}

func exampleIaCIssue() *snyk.Issue {
	return &snyk.Issue{
		ID:               "SNYK-CC-K8S-44",
		Severity:         types.High,
		IssueType:        types.InfrastructureIssue,
		AffectedFilePath: "/workspace/k8s/deployment.yaml",
		Range: types.Range{
			Start: types.Position{Line: 141, Character: 2},
			End:   types.Position{Line: 141, Character: 14},
		},
		Message:          "The role uses wildcards, which grant the role permissions to the whole cluster (Snyk)",
		FormattedMessage: "\n### SNYK-CC-K8S-44: Role or ClusterRole with too wide permissions\n",
		Product:          "Snyk IaC",
		AdditionalData: snyk.IaCIssueData{
			Key:           "iac-example-key",
			Title:         "Role or ClusterRole with too wide permissions",
			PublicId:      "SNYK-CC-K8S-44",
			Documentation: "https://security.snyk.io/rules/cloud/SNYK-CC-K8S-44",
			LineNumber:    141,
			Issue:         "The role uses wildcards, which grant the role permissions to the whole cluster",
			Impact:        "Wildcard rights grant excessive permissions to the Kubernetes API.",
			Resolve:       "Set only the necessary permissions required.",
			Path:          []string{"[DocId: 5]", "rules[0]", "verbs"},
			References: []string{
				"https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
			},
		},
	}
}

func exampleSecretsIssue() *snyk.Issue {
	return &snyk.Issue{
		ID:               "aws-access-token",
		Severity:         types.High,
		AffectedFilePath: "/workspace/config/secrets.go",
		CWEs:             []string{"CWE-798"},
		Range: types.Range{
			Start: types.Position{Line: 10, Character: 5},
			End:   types.Position{Line: 10, Character: 40},
		},
		AdditionalData: snyk.SecretsIssueData{
			Key:        "secret-example-key",
			Title:      "AWS Access Token",
			Message:    "Detected a hardcoded AWS access token",
			RuleId:     "aws-access-token",
			RuleName:   "AWS Access Token Rule",
			CWE:        []string{"CWE-798"},
			Categories: []string{"Security"},
		},
	}
}

// replaceIDEPlaceholders mirrors what scripts/tree-view/main.go does — IDEs would
// normally do this substitution server-side. Keeping the markup simple keeps the
// rendered HTML focused on the panel content rather than IDE chrome.
func replaceIDEPlaceholders(html string) string {
	const nonce = "demo-nonce-12345"
	html = strings.ReplaceAll(html, "${nonce}", nonce)
	html = strings.ReplaceAll(html, "ideNonce", nonce)
	html = strings.ReplaceAll(html, "${headerEnd}", "")
	html = strings.ReplaceAll(html, "${cspSource}", "")
	html = strings.ReplaceAll(html, "${ideStyle}", fmt.Sprintf(`<style nonce="%s">body{background-color:#252526;color:#cccccc;font-family:ui-sans-serif,"SF Pro Text","Segoe UI",sans-serif;}</style>`, nonce))
	html = strings.ReplaceAll(html, "${ideScript}", fmt.Sprintf(`<script nonce="%s">window.__ideExecuteCommand__=function(cmd,args){console.log("[IDE]",cmd,args);};</script>`, nonce))
	html = strings.ReplaceAll(html, "${ideGenerateAIFix}", "")
	html = strings.ReplaceAll(html, "${ideApplyAIFix}", "")
	html = strings.ReplaceAll(html, "${ideSubmitIgnoreRequest}", "")
	html = strings.ReplaceAll(html, "${ideFunc}", "")
	return html
}
