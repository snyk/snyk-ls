package iac

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
)

func Test_IaC_Html_getIacHtml(t *testing.T) {
	cfg := &config.Config{}

	// Initialize the IaC service
	service, _ := NewIacHtmlRenderer(cfg)
	iacPanelHtml := service.getCustomUIContent(createIacIssueSample())

	// assert
	assert.Contains(t, iacPanelHtml, "<!DOCTYPE html>", "HTML should contain the doctype declaration")
	assert.Contains(t, iacPanelHtml, "<meta http-equiv=\"Content-Security-Policy\"", "HTML should contain the CSP meta tag")
	assert.Contains(t, iacPanelHtml, "nonce=", "HTML should include a nonce")
	assert.Contains(t, iacPanelHtml, "<style nonce=", "Style tag should contain the nonce attribute")

	// Check for the presence of specific issue details
	assert.Contains(t, iacPanelHtml, "Role or ClusterRole with too wide permissions", "HTML should contain the issue title")
	assert.Contains(t, iacPanelHtml, "The role uses wildcards, which grant the role permissions to the whole cluster", "HTML should contain the issue description")
	assert.Contains(t, iacPanelHtml, "Set only the necessary permissions required", "HTML should contain the remediation instructions")

	// Path is correctly formatted
	assert.Contains(t, iacPanelHtml, "[DocId: 5] > rules[0] > verbs", "HTML should contain the path to the affected file")

	// Issue ID is present and linked correctly
	assert.Contains(t, iacPanelHtml, `href="https://security.snyk.io/rules/cloud/SNYK-CC-K8S-44">SNYK-CC-K8S-44</a>`, "HTML should contain a link to the issue documentation")

	// Severity icon is rendered
	assert.Contains(t, iacPanelHtml, `<div class="severity-container">`, "HTML should contain the severity icon container")

	// Reference section
	assert.Contains(t, iacPanelHtml, `<a class="styled-link"  rel="noopener noreferrer" href="https://kubernetes.io/docs/reference/access-authn-authz/rbac/">https://kubernetes.io/docs/reference/access-authn-authz/rbac/</a>`, "HTML should contain the first reference")
	assert.Contains(t, iacPanelHtml, `<a class="styled-link"  rel="noopener noreferrer" href="https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole">https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole</a>`, "HTML should contain the second reference")
}

func createIacIssueSample() snyk.Issue {
	issueURL, _ := url.Parse("https://security.snyk.io/rules/cloud/SNYK-CC-K8S-44")

	return snyk.Issue{
		ID:            "SNYK-CC-K8S-44",
		Severity:      1,
		IssueType:     5,
		IsIgnored:     false,
		IgnoreDetails: nil, // No ignore details provided
		Range: snyk.Range{
			Start: snyk.Position{Line: 141, Character: 2},
			End:   snyk.Position{Line: 141, Character: 14},
		},
		Message:             "The role uses wildcards, which grant the role permissions to the whole cluster (Snyk)",
		FormattedMessage:    "\n### SNYK-CC-K8S-44: Role or ClusterRole with too wide permissions\n\n**Issue:** The role uses wildcards, which grant the role permissions to the whole cluster\n\n**Impact:** The use of wildcard rights grants is likely to provide excessive rights to the Kubernetes API. For a ClusterRole this would be considered high severity.\n\n**Resolve:** Set only the necessary permissions required\n",
		AffectedFilePath:    "/Users/cata/git/playground/dex/examples/k8s/dex.yaml",
		Product:             "Snyk IaC",
		References:          nil, // No references provided
		IssueDescriptionURL: issueURL,
		CodelensCommands:    nil,
		Ecosystem:           "",
		CWEs:                nil,
		CVEs:                nil,
		Fingerprint:         "",
		GlobalIdentity:      "",
		AdditionalData: snyk.IaCIssueData{
			Key:           "6bd172724ee6100d2d062221628921b6",
			Title:         "Role or ClusterRole with too wide permissions",
			PublicId:      "SNYK-CC-K8S-44",
			Documentation: "https://security.snyk.io/rules/cloud/SNYK-CC-K8S-44",
			LineNumber:    141,
			Issue:         "The role uses wildcards, which grant the role permissions to the whole cluster",
			Impact:        "The use of wildcard rights grants is likely to provide excessive rights to the Kubernetes API. For a ClusterRole this would be considered high severity.",
			Resolve:       "Set only the necessary permissions required",
			Path:          []string{"[DocId: 5]", "rules[0]", "verbs"},
			References:    []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/", "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole"},
		},
	}
}
