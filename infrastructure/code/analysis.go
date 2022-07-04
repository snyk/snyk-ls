package code

import "github.com/sourcegraph/go-lsp"

type SarifResponse struct {
	Type     string  `json:"type"`
	Progress float64 `json:"progress"`
	Status   string  `json:"status"`
	Timing   struct {
		FetchingCode int `json:"fetchingCode"`
		Queue        int `json:"queue"`
		Analysis     int `json:"analysis"`
	} `json:"timing"`
	Coverage []struct {
		Files       int    `json:"files"`
		IsSupported bool   `json:"isSupported"`
		Lang        string `json:"lang"`
	} `json:"coverage"`
	Sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name            string `json:"name"`
					SemanticVersion string `json:"semanticVersion"`
					Version         string `json:"version"`
					Rules           []struct {
						ID               string `json:"id"`
						Name             string `json:"name"`
						ShortDescription struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
						Help struct {
							Markdown string `json:"markdown"`
							Text     string `json:"text"`
						} `json:"help"`
						Properties struct {
							Tags               []string `json:"tags"`
							Categories         []string `json:"categories"`
							ExampleCommitFixes []struct {
								CommitURL string `json:"commitURL"`
								Lines     []struct {
									Line       string `json:"line"`
									LineNumber int    `json:"lineNumber"`
									LineChange string `json:"lineChange"`
								} `json:"lines"`
							} `json:"exampleCommitFixes"`
							ExampleCommitDescriptions []string `json:"exampleCommitDescriptions"`
							Precision                 string   `json:"precision"`
							RepoDatasetSize           int      `json:"repoDatasetSize"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text      string   `json:"text"`
					Markdown  string   `json:"markdown"`
					Arguments []string `json:"arguments"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine   int `json:"startLine"`
							EndLine     int `json:"endLine"`
							StartColumn int `json:"startColumn"`
							EndColumn   int `json:"endColumn"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Fingerprints struct {
					Num0 string `json:"0"`
					Num1 string `json:"1"`
				} `json:"fingerprints"`
				CodeFlows []struct {
					ThreadFlows []struct {
						Locations []struct {
							Location struct {
								ID               int `json:"id"`
								PhysicalLocation struct {
									ArtifactLocation struct {
										URI       string `json:"uri"`
										URIBaseID string `json:"uriBaseId"`
									} `json:"artifactLocation"`
									Region struct {
										StartLine   int `json:"startLine"`
										EndLine     int `json:"endLine"`
										StartColumn int `json:"startColumn"`
										EndColumn   int `json:"endColumn"`
									} `json:"region"`
								} `json:"physicalLocation"`
							} `json:"location"`
						} `json:"locations"`
					} `json:"threadFlows"`
				} `json:"codeFlows"`
				Properties struct {
					PriorityScore        int `json:"priorityScore"`
					PriorityScoreFactors []struct {
						Label bool   `json:"label"`
						Type  string `json:"type"`
					} `json:"priorityScoreFactors"`
				} `json:"properties"`
			} `json:"results"`
			Properties struct {
				Coverage []struct {
					Files       int    `json:"files"`
					IsSupported bool   `json:"isSupported"`
					Lang        string `json:"lang"`
				} `json:"coverage"`
			} `json:"properties"`
		} `json:"runs"`
	} `json:"sarif"`
}

type AnalysisRequestKey struct {
	Type         string            `json:"type"`
	Hash         string            `json:"hash"`
	LimitToFiles []lsp.DocumentURI `json:"limitToFiles,omitempty"`
	Shard        string            `json:"shard"`
}

type AnalysisContextOrg struct {
	Name        string          `json:"name"`
	DisplayName string          `json:"displayName"`
	PublicId    string          `json:"publicId"`
	Flags       map[string]bool `json:"flags"`
}

type AnalysisContext struct {
	Initiatior string             `json:"initiatior"`
	Flow       string             `json:"flow,omitempty"`
	Org        AnalysisContextOrg `json:"org,omitempty"`
}

type AnalysisRequest struct {
	Key             AnalysisRequestKey `json:"key"`
	Severity        int                `json:"severity,omitempty"`
	Prioritized     bool               `json:"prioritized,omitempty"`
	Legacy          bool               `json:"legacy"`
	AnalysisContext AnalysisContext    `json:"analysisContext"`
}

type SnykAnalysisFailedError struct {
	Msg string
}

func (e SnykAnalysisFailedError) Error() string { return e.Msg }
