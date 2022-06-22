package workspace

import (
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/concurrency"
)

type FolderStatus int
type ProductLine string
type ProductLineAttributes map[string]interface{}

const (
	Unscanned FolderStatus = iota
	Scanned   FolderStatus = iota

	SnykCode       ProductLine = "Snyk Code"
	SnykOpenSource ProductLine = "Snyk Open Source"
	SnykIac        ProductLine = "Snyk IaC"
)

type Folder struct {
	parent                  *Workspace
	path                    string
	name                    string
	status                  FolderStatus
	productLineAttributes   map[ProductLine]ProductLineAttributes
	ignorePatterns          []string
	documentDiagnosticCache concurrency.AtomicMap //fixme
	cli                     cli.Executor          //fixme
}
