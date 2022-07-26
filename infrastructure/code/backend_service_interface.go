package code

import (
	"context"

	"github.com/snyk/snyk-ls/domain/snyk"
)

type AnalysisOptions struct {
	bundleHash   string
	shardKey     string
	limitToFiles []string
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
		[]snyk.Issue,
		AnalysisStatus,
		error,
	)
}
