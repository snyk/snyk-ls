This is a scanner implementation example. See `infrastructure/snyk/scanner/emoji.go` for the implementation.

```go
// code from `infrastructure/snyk/scanner/emoji.go`
package emoji

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/snyk"
)

const (
	catsEvilProof = "https://www.scmp.com/yp/discover/lifestyle/features/article/3071676/13-reasons-why-cats-are-just-plain-evil"
)

type EmojiScanner struct {
	errorReporter    error_reporting.ErrorReporter
	catsEvilProofUrl *url.URL
}

func New(errorReporter error_reporting.ErrorReporter) *EmojiScanner {
	catsEvilProofUrl, _ := url.Parse(catsEvilProof)

	return &EmojiScanner{
		errorReporter,
		catsEvilProofUrl,
	}
}

func (sc *EmojiScanner) Scan(ctx context.Context, path string, folderPath string) []types.Issue {
	fileInfo, err := os.Stat(path)
	if err != nil {
		// error handling
		sc.errorReporter.CaptureError(err)
		log.Err(err).Str("method", "emoji.Scan").Msg("Error while getting file info.")
	}

	if fileInfo.IsDir() {
		// our scanner don't need to scan folders, instead we operate on a file basis.
		return []types.Issue{}
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		sc.errorReporter.CaptureError(err)
		log.Err(err).Str("method", "emoji.Scan").Msg("Error while reading a file")
	}

	emojiRegexp := regexp.MustCompile(`\x{1F408}`) // 🐈 cat emoji regexp

	issues := make([]types.Issue, 0)

	lines := strings.Split(strings.ReplaceAll(string(bytes), "\r", ""), "\n") // split lines
	for i, line := range lines {
		locs := emojiRegexp.FindAllStringIndex(line, len(line))
		if locs == nil {
			continue // no cat emoji found
		}

		for _, loc := range locs {
			r := snyk.Range{
				Start: snyk.Position{Line: i, Character: loc[0]},
				End:   snyk.Position{Line: i, Character: loc[0] + 1},
			}

			textEdit := snyk.TextEdit{
				Range:   r,
				NewText: "woof!",
			}
			replaceCodeAction := snyk.CodeAction{
				Title: "Replace with 🐕",
				Edit: snyk.WorkspaceEdit{
					Changes: map[string][]snyk.TextEdit{
						path: {textEdit},
					},
				},
			}
			learnCodeAction := snyk.CodeAction{
				Title: "Learn why cats are evil",
				Command: snyk.Command{
					Title:     "Learn why",
					Command:   snyk.OpenBrowserCommand,
					Arguments: []interface{}{sc.catsEvilProofUrl.String()},
				},
			}

			issue := snyk.NewIssue(
				"So now you know",
				types.Low,
				snyk.EmojiIssue,
				r,
				"Cats are not allowed in this project",
				sc.GetFormattedMessage(),
				path,
				sc.Product(),
				[]types.Reference{},
				sc.catsEvilProofUrl,
				[]snyk.CodeAction{replaceCodeAction, learnCodeAction},
				[]snyk.Command{},
			)

			issues = append(issues, issue)
		}
	}

	return issues
}

func (sc *EmojiScanner) IsEnabled() bool {
	return true
}

func (sc *EmojiScanner) Product() snyk.Product {
	return snyk.ProductEmoji
}

func (sc *EmojiScanner) GetFormattedMessage() string {
	return fmt.Sprintf("## Cats are evil \n You can find proof by navigating to [this link](%s)", catsEvilProof)
}
```
