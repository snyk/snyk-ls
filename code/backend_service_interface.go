package code

import (
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/lsp"
)

type SnykCodeClient interface {
	GetFilters() (configFiles []string, extensions []string, err error)

	CreateBundle(files map[sglsp.DocumentURI]BundleFile) (string, []sglsp.DocumentURI, error)

	ExtendBundle(
		bundleHash string,
		files map[sglsp.DocumentURI]BundleFile,
		removedFiles []sglsp.DocumentURI,
	) (string, []sglsp.DocumentURI, error)

	RunAnalysis(
		bundleHash string,
		shardKey string,
		limitToFiles []sglsp.DocumentURI,
		severity int,
	) (
		map[sglsp.DocumentURI][]lsp.Diagnostic,
		map[sglsp.DocumentURI][]lsp.HoverDetails,
		string,
		error,
	)
}
