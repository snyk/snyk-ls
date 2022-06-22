package workspace

import (
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/concurrency"
)

type WorkspaceFolderStatus int
type ProductLine string
type ProductLineAttributes map[string]interface{}

const (
	Unscanned WorkspaceFolderStatus = iota
	Scanned   WorkspaceFolderStatus = iota

	SnykCode       ProductLine = "Snyk Code"
	SnykOpenSource ProductLine = "Snyk Open Source"
	SnykIac        ProductLine = "Snyk IaC"
)

type Folder struct {
	parent                  *Workspace
	path                    string
	name                    string
	status                  WorkspaceFolderStatus
	productLineAttributes   map[ProductLine]ProductLineAttributes
	ignorePatterns          []string
	documentDiagnosticCache concurrency.AtomicMap
	cli                     cli.Executor
}
