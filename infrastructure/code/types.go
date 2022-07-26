package code

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
		Runs    []run  `json:"runs"`
	} `json:"sarif"`
}

type region struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartColumn int `json:"startColumn"`
	EndColumn   int `json:"endColumn"`
}

type artifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region"`
}

type location struct {
	ID               int              `json:"id"`
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type threadFlowLocation struct {
	Location location `json:"location"`
}

type threadFlow struct {
	Locations []threadFlowLocation `json:"locations"`
}

type codeFlow struct {
	ThreadFlows []threadFlow `json:"threadFlows"`
}

type resultMessage struct {
	Text      string   `json:"text"`
	Markdown  string   `json:"markdown"`
	Arguments []string `json:"arguments"`
}

type fingerprints struct {
	Num0 string `json:"0"`
	Num1 string `json:"1"`
}

type resultProperties struct {
	PriorityScore        int `json:"priorityScore"`
	PriorityScoreFactors []struct {
		Label bool   `json:"label"`
		Type  string `json:"type"`
	} `json:"priorityScoreFactors"`
}

type result struct {
	RuleID       string           `json:"ruleId"`
	RuleIndex    int              `json:"ruleIndex"`
	Level        string           `json:"level"`
	Message      resultMessage    `json:"message"`
	Locations    []location       `json:"locations"`
	Fingerprints fingerprints     `json:"fingerprints"`
	CodeFlows    []codeFlow       `json:"codeFlows"`
	Properties   resultProperties `json:"ruleProperties"`
}

type exampleCommitFix struct {
	CommitURL string `json:"commitURL"`
	Lines     []struct {
		Line       string `json:"line"`
		LineNumber int    `json:"lineNumber"`
		LineChange string `json:"lineChange"`
	} `json:"lines"`
}

type help struct {
	Markdown string `json:"markdown"`
	Text     string `json:"text"`
}

type ruleProperties struct {
	Tags                      []string           `json:"tags"`
	Categories                []string           `json:"categories"`
	ExampleCommitFixes        []exampleCommitFix `json:"exampleCommitFixes"`
	ExampleCommitDescriptions []string           `json:"exampleCommitDescriptions"`
	Precision                 string             `json:"precision"`
	RepoDatasetSize           int                `json:"repoDatasetSize"`
}

type defaultConfiguration struct {
	Level string `json:"level"`
}

type shortDescription struct {
	Text string `json:"text"`
}

type rule struct {
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	ShortDescription     shortDescription     `json:"shortDescription"`
	DefaultConfiguration defaultConfiguration `json:"defaultConfiguration"`
	Help                 help                 `json:"help"`
	Properties           ruleProperties       `json:"properties"`
}

type driver struct {
	Name            string `json:"name"`
	SemanticVersion string `json:"semanticVersion"`
	Version         string `json:"version"`
	Rules           []rule `json:"rules"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type runProperties struct {
	Coverage []struct {
		Files       int    `json:"files"`
		IsSupported bool   `json:"isSupported"`
		Lang        string `json:"lang"`
	} `json:"coverage"`
}

type run struct {
	Tool       tool          `json:"tool"`
	Results    []result      `json:"results"`
	Properties runProperties `json:"ruleProperties"`
}

type AnalysisRequestKey struct {
	Type         string   `json:"type"`
	Hash         string   `json:"hash"`
	LimitToFiles []string `json:"limitToFiles,omitempty"`
	Shard        string   `json:"shard"`
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
