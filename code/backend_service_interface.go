package code

import (
	"context"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/lsp"
)

type SnykCodeClient interface {
	GetFilters(ctx context.Context, requestId string) (configFiles []string, extensions []string, err error)

	CreateBundle(
		ctx context.Context,
		files map[sglsp.DocumentURI]BundleFile,
		requestId string,
	) (string, []sglsp.DocumentURI, error)

	ExtendBundle(
		ctx context.Context,
		bundleHash string,
		files map[sglsp.DocumentURI]BundleFile,
		removedFiles []sglsp.DocumentURI,
		requestId string,
	) (string, []sglsp.DocumentURI, error)

	RunAnalysis(
		ctx context.Context,
		bundleHash string,
		shardKey string,
		limitToFiles []sglsp.DocumentURI,
		severity int,
		requestId string,
	) (
		map[sglsp.DocumentURI][]lsp.Diagnostic,
		map[sglsp.DocumentURI][]lsp.HoverDetails,
		AnalysisStatus,
		error,
	)
}
