package ide

import "github.com/snyk/snyk-ls/domain/snyk"

// IssueProvider is an interface that allows to retrieve issues for a given path and range.
// This is used instead of any concrete dependency to allow for easier testing and more flexibility in implementation.
type IssueProvider interface {
	IssuesFor(path string, r snyk.Range) []snyk.Issue
}
