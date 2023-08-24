package parser

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/net/html"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
)

var (
	pathBased = []string{
		"https://maxcdn.bootstrapcdn.com/",
		"https://yastatic.net/",
		"https://stackpath.bootstrapcdn.com/",
	}
	atBased   = []string{"https://cdn.jsdelivr.net/", "https://unpkg.com/"}
	jQuery    = "https://code.jquery.com/"
	aspNetCDN = "https://ajax.aspnetcdn.com/ajax/"
)

type htmlParser struct {
	config *config.Config
}

func (h htmlParser) Parse(filePath string) (dependencies []Dependency, err error) {
	logger := h.config.Logger().With().Str("method", "htmlParser.Parse").Str("file", filePath).Logger()

	bytes, err := os.ReadFile(filePath)
	if err != nil {
		logger.Err(err).Msg("couldn't read file")
		return nil, err
	}
	fileContent := string(bytes)

	doc, err := html.Parse(strings.NewReader(fileContent))
	if err != nil {
		logger.Err(err).Msg("couldn't parse file")
	}

	deps := extractSrc(doc)
	dependencies, err = h.parseDependencies(deps, fileContent)
	if err != nil {
		logger.Err(err).Msg("couldn't extract dependencies")
		return nil, err
	}
	return dependencies, nil
}

func (h htmlParser) parseDependencies(deps []string, fileContent string) (dependencies []Dependency, err error) {
	logger := h.config.Logger().With().Str("method", "htmlParser.parseDependencies").Logger()
	for _, dep := range deps {
		dependency, err := h.dependencyFromString(dep)
		if err != nil {
			continue
		}
		logger.Trace().Msgf("found dependency: %s", dependency)
		before, _, found := strings.Cut(fileContent, dep)
		if !found {
			return nil, fmt.Errorf("couldn't find dependency %s in file content", dep)
		}
		line := strings.Count(before, "\n")
		absPosDep := strings.Index(fileContent, dep)
		linePos := absPosDep - strings.LastIndex(before, "\n")
		dependency.Range = snyk.Range{
			Start: snyk.Position{
				Line:      line,
				Character: linePos,
			},
			End: snyk.Position{
				Line:      line,
				Character: len(dep) + linePos,
			},
		}

		dependencies = append(dependencies, *dependency)
	}
	return dependencies, nil
}

func (h htmlParser) getPackageFromURL(url string) string {
	lowerURL := strings.ToLower(url)
	i := strings.Index(lowerURL, "/ajax/libs/")
	url = strings.ReplaceAll(url, ".slim.js", "")
	url = strings.ReplaceAll(url, ".min.js", "")

	if i != -1 {
		i += len("/ajax/libs/")
		pkg := url[i:]
		parts := strings.Split(pkg, "/")
		name := parts[0]
		version := "latest"
		if len(parts) > 1 {
			version = parts[1]
		}
		return name + "@" + version
	}

	var isPathBased string
	for _, source := range pathBased {
		if strings.HasPrefix(lowerURL, source) {
			isPathBased = source
			break
		}
	}
	if isPathBased != "" {
		pkg := url[len(isPathBased):]
		separator := "/"
		if strings.Contains(pkg, "-") {
			separator = "-"
		}
		parts := strings.Split(pkg, separator)
		name := parts[0]
		version := "latest"
		if len(parts) > 1 {
			version = parts[1]
		}
		return name + "@" + version
	}

	if strings.HasPrefix(lowerURL, jQuery) {
		pkg := url[len(jQuery):]
		parts := strings.Split(pkg, "-")
		name := parts[0]
		version := strings.Join(parts[1:], "-")
		return name + "@" + version
	}

	if strings.HasPrefix(lowerURL, aspNetCDN) {
		pkg := url[len(aspNetCDN):]
		parts := strings.Split(pkg, "-")
		nameParts := strings.Split(parts[0], "/")
		name := nameParts[len(nameParts)-1]
		version := strings.Join(parts[1:], "-")
		return name + "@" + version
	}

	var isAtBased string
	for _, source := range atBased {
		if strings.HasPrefix(lowerURL, source) {
			isAtBased = source
			break
		}
	}
	if isAtBased != "" {
		parts := strings.Split(url[len(isAtBased):], "/")
		var pkg string
		for _, str := range parts {
			if strings.Contains(str, "@") {
				pkg = str
				break
			}
		}
		return pkg
	}

	return ""
}

func (h htmlParser) dependencyFromString(dep string) (dependency *Dependency, err error) {
	p := h.getPackageFromURL(dep)
	if p == "" {
		return nil, fmt.Errorf("couldn't parse dependency from %s", dep)
	}
	parts := strings.Split(p, "@")
	dependency = &Dependency{
		ArtifactID: parts[0],
		Version:    parts[1],
	}
	return dependency, nil
}

func extractSrc(n *html.Node) []string {
	deps := []string{}
	if n.Type == html.ElementNode && n.Data == "script" {
		for _, attr := range n.Attr {
			if attr.Key == "src" {
				deps = append(deps, attr.Val)
			}
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		deps = append(deps, extractSrc(c)...)
	}
	return deps
}

func NewHTMLParser(config *config.Config) DependencyParser {
	return &htmlParser{config: config}
}
