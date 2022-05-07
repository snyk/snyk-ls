package oss

import (
	"context"
	"strings"

	"github.com/sourcegraph/go-lsp"
)

type NpmRangeFinder struct {
	uri         lsp.DocumentURI
	fileContent []byte
	myRange     lsp.Range
}

func (n *NpmRangeFinder) Find(ctx context.Context, issue ossIssue) lsp.Range {
	searchPackage, version := introducingPackageAndVersion(ctx, issue)
	var lines = strings.Split(strings.ReplaceAll(string(n.fileContent), "\r\n", "\n"), "\n")

	var start lsp.Position
	var end lsp.Position

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		logger.
			WithField("method", "NpmRangeFinder.Find").
			WithField("searchPackage", searchPackage).
			WithField("searchVersion", version).
			WithField("issueId", issue.Id).
			WithField("line", line).
			Trace(ctx, "searching...")
		elems := strings.Split(line, ":")
		if len(elems) > 1 {
			jsonKey := strings.Trim(strings.Trim(elems[0], " "), "\"")
			if jsonKey == searchPackage {
				start.Line = i
				start.Character = strings.Index(line, searchPackage) - 1
				end.Line = i
				end.Character = len(strings.ReplaceAll(line, ",", ""))
				logger.
					WithField("method", "NpmRangeFinder.Find").
					WithField("issueId", issue.Id).
					WithField("start", start).
					WithField("end", end).
					Trace(ctx, "found range for "+searchPackage)
				break
			}
		}
	}

	n.myRange = lsp.Range{
		Start: start,
		End:   end,
	}
	return n.myRange
}

func introducingPackageAndVersion(ctx context.Context, issue ossIssue) (string, string) {
	var packageName string
	var version string
	if len(issue.From) > 1 {
		split := strings.Split(issue.From[1], "@")
		packageSplit := split[0]
		switch issue.PackageManager {
		case "maven":
			index := strings.LastIndex(packageSplit, ":")
			packageName = packageSplit[index+1:]
		default:
			packageName = packageSplit
		}
		version = split[1]
	} else {
		packageName = issue.Name
		version = issue.Version
	}
	logger.
		WithField("method", "NpmRangeFinder.introducingPackageAndVersion").
		WithField("IntroducingPackage", packageName).
		WithField("IntroducingVersion", version).
		WithField("issueId", issue.Id).
		Trace(ctx, "Introducing package and version")
	return packageName, version
}
