package code

import (
	"context"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/ide/hover"
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
		files map[string]string,
	) (newBundleHash string, missingFiles []string, err error)

	ExtendBundle(
		ctx context.Context,
		bundleHash string,
		files map[string]BundleFile,
		removedFiles []string,
	) (newBundleHash string, missingFiles []string, err error)

	RunAnalysis(
		ctx context.Context,
		options AnalysisOptions,
	) (
		map[string][]lsp.Diagnostic,
		map[sglsp.DocumentURI][]hover.Hover,
		AnalysisStatus,
		error,
	)
}
