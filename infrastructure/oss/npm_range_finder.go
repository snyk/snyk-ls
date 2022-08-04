package oss

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/snyk"
)

type NpmRangeFinder struct {
	uri         lsp.DocumentURI
	fileContent []byte
	myRange     snyk.Range
}

func (n *NpmRangeFinder) find(issue ossIssue) snyk.Range {
	searchPackage, _ := introducingPackageAndVersion(issue)
	var lines = strings.Split(strings.ReplaceAll(string(n.fileContent), "\r\n", "\n"), "\n")

	var start snyk.Position
	var end snyk.Position

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

	n.myRange = snyk.Range{
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
		splitArrayLength := len(split)
		packageSplit := split[splitArrayLength-2]
		if splitArrayLength > 2 {
			// handle scoped packages
			packageSplit = fmt.Sprintf("@%s", split[splitArrayLength-2])
		}
		switch issue.PackageManager {
		case "maven":
			index := strings.LastIndex(packageSplit, ":")
			packageName = packageSplit[index+1:]
		default:
			packageName = packageSplit
		}
		version = split[splitArrayLength-1]
	} else {
		packageName = issue.Name
		version = issue.Version
	}
	log.Trace().Str("issueId", issue.Id).Str("IntroducingPackage", packageName).Str("IntroducingVersion", version).Msg("Introducing package and version")
	return packageName, version
}
