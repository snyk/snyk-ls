package code

import (
	"context"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/lsp"
)

type SnykCodeService interface {
	CreateBundle(
		ctx context.Context,
		files map[sglsp.DocumentURI]File,
	) (string, []sglsp.DocumentURI, error)

	ExtendBundle(
		ctx context.Context,
		bundleHash string,
		files map[sglsp.DocumentURI]File,
		removedFiles []sglsp.DocumentURI,
	) (string, []sglsp.DocumentURI, error)

	RunAnalysis(
		ctx context.Context,
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
