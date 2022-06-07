package code

import (
	"context"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/lsp"
)

type AnalysisOptions struct {
	bundleHash   string
	shardKey     string
	limitToFiles []sglsp.DocumentURI
	severity     int
}

type SnykCodeClient interface {
	GetFilters(ctx context.Context) (configFiles []string, extensions []string, err error)

	CreateBundle(
		ctx context.Context,
		files map[sglsp.DocumentURI]BundleFile,
	) (string, []sglsp.DocumentURI, error)

	ExtendBundle(
		ctx context.Context,
		bundleHash string,
		files map[sglsp.DocumentURI]BundleFile,
		removedFiles []sglsp.DocumentURI,
	) (string, []sglsp.DocumentURI, error)

	RunAnalysis(
		ctx context.Context,
		options AnalysisOptions,
	) (
		map[sglsp.DocumentURI][]lsp.Diagnostic,
		map[sglsp.DocumentURI][]lsp.HoverDetails,
		AnalysisStatus,
		error,
	)
}
