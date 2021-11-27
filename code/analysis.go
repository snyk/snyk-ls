package code

import (
	"github.com/sourcegraph/go-lsp"
)

type AnalysisRequestKey struct {
	Type         string            `json:"type"`
	Hash         string            `json:"hash"`
	LimitToFiles []lsp.DocumentURI `json:"limitToFiles"`
}

type AnalysisRequest struct {
	Key         AnalysisRequestKey `json:"key"`
	Severity    int                `json:"severity"`
	Prioritized int                `json:"prioritized"`
	Legacy      bool               `json:"legacy"`
}

type Marker struct {
	Msg []int `json:"msg"`
	Pos []int `json:"pos"`
}

type FilePosition struct {
	Rows   []int    `json:"rows"`
	Cols   []int    `json:"cols"`
	Marker []Marker `json:"marker"`
}

type FileSuggestions map[string][]FilePosition

type AnalysisSeverity struct{}

type CommitChangeLine struct {
	Line       string `json:"line"`
	LineNumber int    `json:"lineNumber"`
	LineChange string `json:"lineChange"`
}

type ExampleCommitFix struct {
	CommitURL string             `json:"commitURL"`
	Lines     []CommitChangeLine `json:"lines"`
}

type Suggestion struct {
	Id                        string             `json:"id"`
	Message                   string             `json:"message"`
	Severity                  int                `json:"severity"`
	LeadURL                   string             `json:"leadURL"`
	Rule                      string             `json:"rule"`
	Tags                      []string           `json:"tags"`
	Categories                []string           `json:"categories"`
	RepoDatasetSize           int                `json:"repoDatasetSize"`
	ExampleCommitDescriptions []string           `json:"exampleCommitDescriptions"`
	ExampleCommitFixes        []ExampleCommitFix `json:"exampleCommitFixes"`
	Cwe                       []string           `json:"cwe"`
	Title                     string             `json:"title"`
	Text                      string             `json:"text"`
}

type AnalysisResponse struct {
	Status      string                              `json:"status"`
	Progress    int                                 `json:"progress"`
	Files       map[lsp.DocumentURI]FileSuggestions `json:"files"`
	Suggestions map[string]Suggestion               `json:"suggestions"`
}

type SnykAnalysisFailedError struct {
	Msg string
}

func (e SnykAnalysisFailedError) Error() string { return e.Msg }
