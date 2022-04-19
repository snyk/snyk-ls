package oss

import (
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/go-lsp"
)

type NpmRangeFinder struct {
	uri         lsp.DocumentURI
	fileContent []byte
	myRange     lsp.Range
}

func (n *NpmRangeFinder) Find(issue ossIssue) lsp.Range {
	searchPackage, _ := introducingPackageAndVersion(issue)
	var lines = strings.Split(strings.ReplaceAll(string(n.fileContent), "\r\n", "\n"), "\n")

	var start lsp.Position
	var end lsp.Position

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		log.Trace().Interface("issueId", issue.Id).Str("line", line).Msg("scanning line for " + searchPackage)
		elems := strings.Split(line, ":")
		if len(elems) > 1 {
			jsonKey := strings.Trim(strings.Trim(elems[0], " "), "\"")
			if jsonKey == searchPackage {
				start.Line = i
				start.Character = strings.Index(line, searchPackage) - 1
				end.Line = i
				end.Character = len(strings.ReplaceAll(line, ",", ""))
				log.Trace().Str("issueId", issue.Id).Interface("start", start).Interface("end", end).Msg("found range for " + searchPackage)
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

func introducingPackageAndVersion(issue ossIssue) (string, string) {
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
	log.Trace().Str("issueId", issue.Id).Str("IntroducingPackage", packageName).Str("IntroducingVersion", version).Msg("Introducing package and version")
	return packageName, version
}
