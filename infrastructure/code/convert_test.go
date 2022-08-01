package code

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adrg/xdg"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func getSarifResponseJson(filePath string) string {
	filePath = strings.ReplaceAll(filePath, `\`, `\\`)
	return fmt.Sprintf(`{
  "type": "sarif",
  "progress": 1,
  "status": "COMPLETE",
  "timing": {
    "fetchingCode": 2,
    "queue": 22,
    "analysis": 3015
  },
  "coverage": [
    {
      "files": 1,
      "isSupported": false,
      "lang": "DIGITAL Command Language"
    },
    {
      "files": 1,
      "isSupported": true,
      "lang": "Java"
    }
  ],
  "sarif": {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [
      {
        "tool": {
          "driver": {
            "name": "SnykCode",
            "semanticVersion": "1.0.0",
            "version": "1.0.0",
            "rules": [
              {
                "id": "java/DontUsePrintStackTrace",
                "name": "DontUsePrintStackTrace",
                "shortDescription": {
                  "text": "DontUsePrintStackTrace"
                },
                "defaultConfiguration": {
                  "level": "note"
                },
                "help": {
                  "markdown": "",
                  "text": ""
                },
                "properties": {
                  "tags": [
                    "java",
                    "maintenance",
                    "bug",
                    "logging",
                    "exception",
                    "error"
                  ],
                  "categories": [
                    "Defect"
                  ],
                  "exampleCommitFixes": [
                    {
                      "commitURL": "https://github.com/apache/flink/commit/5d7c5620804eddd59206b24c87ffc89c12fd1184?diff=split#diff-86ec3e3884662ba3b5f4bb5050221fd6L94",
                      "lines": [
                        {
                          "line": "try {",
                          "lineNumber": 101,
                          "lineChange": "none"
                        },
                        {
                          "line": "  newCopy.read(dis);",
                          "lineNumber": 102,
                          "lineChange": "none"
                        },
                        {
                          "line": "} catch (IOException e) {",
                          "lineNumber": 103,
                          "lineChange": "none"
                        },
                        {
                          "line": "  e.printStackTrace();",
                          "lineNumber": 94,
                          "lineChange": "removed"
                        },
                        {
                          "line": "  LOG.error(e);",
                          "lineNumber": 104,
                          "lineChange": "added"
                        },
                        {
                          "line": "}",
                          "lineNumber": 105,
                          "lineChange": "none"
                        }
                      ]
                    },
                    {
                      "commitURL": "https://github.com/rtr-nettest/open-rmbt/commit/0fa9d5547c5300cf8162b8f31a40aea6847a5c32?diff=split#diff-7e23eb1aa3b7b4d5db89bfd2860277e5L75",
                      "lines": [
                        {
                          "line": "  }",
                          "lineNumber": 111,
                          "lineChange": "none"
                        },
                        {
                          "line": "}",
                          "lineNumber": 112,
                          "lineChange": "none"
                        },
                        {
                          "line": "catch (Exception e) {",
                          "lineNumber": 113,
                          "lineChange": "none"
                        },
                        {
                          "line": "  e.printStackTrace();",
                          "lineNumber": 75,
                          "lineChange": "removed"
                        },
                        {
                          "line": "  error(e, 0);",
                          "lineNumber": 114,
                          "lineChange": "added"
                        },
                        {
                          "line": "  state.set(JobState.ERROR);",
                          "lineNumber": 115,
                          "lineChange": "added"
                        },
                        {
                          "line": "}",
                          "lineNumber": 116,
                          "lineChange": "none"
                        },
                        {
                          "line": "finally {",
                          "lineNumber": 117,
                          "lineChange": "none"
                        }
                      ]
                    },
                    {
                      "commitURL": "https://github.com/wso2/developer-studio/commit/cfd84b83349e67de4b0239733bc6ed01287856b7?diff=split#diff-645425e844adc2eab8197719cbb2fe8dL285",
                      "lines": [
                        {
                          "line": "  } catch (SAXException e) {",
                          "lineNumber": 282,
                          "lineChange": "none"
                        },
                        {
                          "line": "    e.printStackTrace();",
                          "lineNumber": 283,
                          "lineChange": "removed"
                        },
                        {
                          "line": "    log.error(e);",
                          "lineNumber": 282,
                          "lineChange": "added"
                        },
                        {
                          "line": "  } catch (IOException e) {",
                          "lineNumber": 284,
                          "lineChange": "none"
                        },
                        {
                          "line": "    e.printStackTrace();",
                          "lineNumber": 285,
                          "lineChange": "removed"
                        },
                        {
                          "line": "    log.error(e);",
                          "lineNumber": 284,
                          "lineChange": "added"
                        },
                        {
                          "line": "  }",
                          "lineNumber": 286,
                          "lineChange": "none"
                        },
                        {
                          "line": "}",
                          "lineNumber": 287,
                          "lineChange": "none"
                        }
                      ]
                    }
                  ],
                  "exampleCommitDescriptions": [
                    "improve logging and testing",
                    "more tests, exceptions",
                    "log errors to the log file"
                  ],
                  "precision": "very-high",
                  "repoDatasetSize": 5854
                }
              },
              {
                "id": "java/catchingInterruptedExceptionWithoutInterrupt",
                "name": "catchingInterruptedExceptionWithoutInterrupt",
                "shortDescription": {
                  "text": "catchingInterruptedExceptionWithoutInterrupt"
                },
                "defaultConfiguration": {
                  "level": "warning"
                },
                "help": {
                  "markdown": "",
                  "text": ""
                },
                "properties": {
                  "tags": [
                    "java",
                    "bug",
                    "maintenance",
                    "import",
                    "remoting.jar",
                    "overwrite"
                  ],
                  "categories": [
                    "Defect"
                  ],
                  "exampleCommitFixes": [
                    {
                      "commitURL": "https://github.com/markusfisch/ShaderEditor/commit/ea90be086b71df55a675a4a75d35c6f294a634a9?diff=split#diff-924648dd89d8c5ea66b90291ac693c9aL739",
                      "lines": [
                        {
                          "line": "    Thread.sleep(100);",
                          "lineNumber": 736,
                          "lineChange": "none"
                        },
                        {
                          "line": "  }",
                          "lineNumber": 737,
                          "lineChange": "none"
                        },
                        {
                          "line": "} catch (InterruptedException e) {",
                          "lineNumber": 738,
                          "lineChange": "none"
                        },
                        {
                          "line": "  // thread got interrupted, ignore that",
                          "lineNumber": 739,
                          "lineChange": "removed"
                        },
                        {
                          "line": "  Thread.currentThread().interrupt();",
                          "lineNumber": 739,
                          "lineChange": "added"
                        },
                        {
                          "line": "}",
                          "lineNumber": 740,
                          "lineChange": "none"
                        }
                      ]
                    },
                    {
                      "commitURL": "https://github.com/yegor256/rexsl/commit/c147bbb780882cdf8e62e4de46b8f99b86d94a5c?diff=split#diff-43fdfda5b43f9f592cb0e8fc194b12ddL64",
                      "lines": [
                        {
                          "line": "       // @checkstyle MagicNumber (1 line)",
                          "lineNumber": 61,
                          "lineChange": "none"
                        },
                        {
                          "line": "       Thread.sleep(1000);",
                          "lineNumber": 62,
                          "lineChange": "none"
                        },
                        {
                          "line": "   } catch (java.lang.InterruptedException ex) {",
                          "lineNumber": 63,
                          "lineChange": "none"
                        },
                        {
                          "line": "       container.stop();",
                          "lineNumber": 64,
                          "lineChange": "none"
                        },
                        {
                          "line": "       Thread.currentThread().interrupt();",
                          "lineNumber": 65,
                          "lineChange": "added"
                        },
                        {
                          "line": "   }",
                          "lineNumber": 66,
                          "lineChange": "none"
                        },
                        {
                          "line": "}",
                          "lineNumber": 67,
                          "lineChange": "none"
                        }
                      ]
                    },
                    {
                      "commitURL": "https://github.com/apache/tomcat/commit/c6bd6f4afbf24c23b3ff03ec652f7e4524694a1e?diff=split#diff-7fc346c0b69fcfdc8e4ad44afc3b345fL85",
                      "lines": [
                        {
                          "line": "        configureTask(worker);",
                          "lineNumber": 82,
                          "lineChange": "none"
                        },
                        {
                          "line": "    } else {",
                          "lineNumber": 83,
                          "lineChange": "none"
                        },
                        {
                          "line": "        try { mutex.wait(); } catch ( java.lang.InterruptedException x ) {Thread.interrupted();}",
                          "lineNumber": 84,
                          "lineChange": "removed"
                        },
                        {
                          "line": "        try {",
                          "lineNumber": 84,
                          "lineChange": "added"
                        },
                        {
                          "line": "            mutex.wait();",
                          "lineNumber": 85,
                          "lineChange": "added"
                        },
                        {
                          "line": "        } catch (java.lang.InterruptedException x) {",
                          "lineNumber": 86,
                          "lineChange": "added"
                        },
                        {
                          "line": "            Thread.currentThread().interrupt();",
                          "lineNumber": 87,
                          "lineChange": "added"
                        },
                        {
                          "line": "        }",
                          "lineNumber": 88,
                          "lineChange": "added"
                        },
                        {
                          "line": "    }",
                          "lineNumber": 89,
                          "lineChange": "none"
                        },
                        {
                          "line": "}//while",
                          "lineNumber": 90,
                          "lineChange": "none"
                        }
                      ]
                    }
                  ],
                  "exampleCommitDescriptions": [
                    "Clean up import statements in java code.",
                    "Overwrite remoting.jar only when necessary."
                  ],
                  "precision": "very-high",
                  "repoDatasetSize": 26
                }
              }
            ]
          }
        },
        "results": [
          {
            "ruleId": "java/DontUsePrintStackTrace",
            "ruleIndex": 0,
            "level": "note",
            "message": {
              "text": "Printing the stack trace of java.lang.InterruptedException. Production code should not use printStackTrace.",
              "markdown": "Printing the stack trace of {0}. Production code should not use {1}.",
              "arguments": [
                "[java.lang.InterruptedException](0)",
                "[printStackTrace](1)"
              ]
            },
            "locations": [
              {
                "physicalLocation": {
                  "artifactLocation": {
                    "uri": "%s",
                    "uriBaseId": "dummy"
                  },
                  "region": {
                    "startLine": 6,
                    "endLine": 6,
                    "startColumn": 7,
                    "endColumn": 7
                  }
                }
              }
            ],
            "fingerprints": {
              "0": "35bc91513238a0a06af1824552fb3f838201f6fbbf1d76632b2604242e838d20",
              "1": "c2e08f55.1333c445.d1699128.15932eef.606b2add.34c3b532.4a752797.e9000d02.c2e08f55.1333c445.cd271e66.e22980a8.d31a8364.2f2c7742.4a752797.54d46e25"
            },
            "codeFlows": [
              {
                "threadFlows": [
                  {
                    "locations": [
                      {
                        "location": {
                          "id": 0,
                          "physicalLocation": {
                            "artifactLocation": {
                              "uri": "%s",
                              "uriBaseId": "dummy"
                            },
                            "region": {
                              "startLine": 5,
                              "endLine": 5,
                              "startColumn": 14,
                              "endColumn": 33
                            }
                          }
                        }
                      },
                      {
                        "location": {
                          "id": 1,
                          "physicalLocation": {
                            "artifactLocation": {
																"uri": "%s",
                              "uriBaseId": "dummy"
                            },
                            "region": {
                              "startLine": 6,
                              "endLine": 6,
                              "startColumn": 9,
                              "endColumn": 23
                            }
                          }
                        }
                      }
                    ]
                  }
                ]
              }
            ],
            "properties": {
              "priorityScore": 550,
              "priorityScoreFactors": [
                {
                  "label": true,
                  "type": "hotFileSource"
                },
                {
                  "label": true,
                  "type": "fixExamples"
                },
                {
                  "label": true,
                  "type": "commonlyFixed"
                }
              ]
            }
          },
          {
            "ruleId": "java/catchingInterruptedExceptionWithoutInterrupt",
            "ruleIndex": 1,
            "level": "warning",
            "message": {
              "text": "Either rethrow this java.lang.InterruptedException or set the interrupted flag on the current thread with 'Thread.currentThread().interrupt()'. Otherwise the information that the current thread was interrupted will be lost.",
              "markdown": "Either rethrow this {0} or set the interrupted flag on the current thread with 'Thread.currentThread().interrupt()'. Otherwise the information that the current thread was interrupted will be lost.",
              "arguments": [
                "[java.lang.InterruptedException](0)"
              ]
            },
            "locations": [
              {
                "physicalLocation": {
                  "artifactLocation": {
                    "uri": "%s",
                    "uriBaseId": "dummy"
                  },
                  "region": {
                    "startLine": 5,
                    "endLine": 5,
                    "startColumn": 7,
                    "endColumn": 35
                  }
                }
              }
            ],
            "fingerprints": {
              "0": "4ee04cfd17e0a8bee301d4741b26962f0a9630ac811ab48c06513857c3319f4c",
              "1": "c2e08f55.1333c445.cd271e66.e22980a8.d31a8364.2f2c7742.4a752797.54d46e25.c2e08f55.1333c445.cd271e66.e22980a8.d31a8364.2f2c7742.4a752797.54d46e25"
            },
            "codeFlows": [
              {
                "threadFlows": [
                  {
                    "locations": [
                      {
                        "location": {
                          "id": 0,
                          "physicalLocation": {
                            "artifactLocation": {
                              "uri": "%s",
                              "uriBaseId": "dummy"
                            },
                            "region": {
                              "startLine": 5,
                              "endLine": 5,
                              "startColumn": 14,
                              "endColumn": 33
                            }
                          }
                        }
                      }
                    ]
                  }
                ]
              }
            ],
            "properties": {
              "priorityScore": 600,
              "priorityScoreFactors": [
                {
                  "label": true,
                  "type": "hotFileSource"
                },
                {
                  "label": true,
                  "type": "fixExamples"
                }
              ]
            }
          }
        ],
        "properties": {
          "coverage": [
            {
              "files": 1,
              "isSupported": false,
              "lang": "DIGITAL Command Language"
            },
            {
              "files": 1,
              "isSupported": true,
              "lang": "Java"
            }
          ]
        }
      }
    ]
  }
}
`, filePath, filePath, filePath, filePath, filePath)
}

func TestSnykCodeBackendService_convert_shouldConvertIssues(t *testing.T) {
	path, issues, _ := setupConversionTests(t)
	issueDescriptionURL, _ := url.Parse(codeDescriptionURL)
	references := referencesForSampleSarifResponse()

	issue := issues[0]

	assert.Equal(t, "java/DontUsePrintStackTrace", issue.ID)
	assert.Equal(t, "Printing the stack trace of java.lang.InterruptedException. Production code should not use printStackTrace. (Snyk)", issue.Message)
	assert.Equal(t, snyk.CodeSecurityVulnerability, issue.IssueType)
	assert.Equal(t, snyk.Low, issue.Severity)
	assert.Equal(t, path, issue.AffectedFilePath)
	assert.Equal(t, snyk.ProductCode, issue.Product)
	assert.Equal(t, issueDescriptionURL, issue.IssueDescriptionURL)
	assert.Equal(t, references, issue.References)
	assert.Contains(t, issue.FormattedMessage, "Example Commit Fixes")
	assert.NotEmpty(t, issue.Commands, "should have getCommands filled from codeflow")
}

func referencesForSampleSarifResponse() []snyk.Reference {

	exampleCommitFix1, _ := url.Parse("https://github.com/apache/flink/commit/5d7c5620804eddd59206b24c87ffc89c12fd1184?diff=split#diff-86ec3e3884662ba3b5f4bb5050221fd6L94")
	exampleCommitFix2, _ := url.Parse("https://github.com/rtr-nettest/open-rmbt/commit/0fa9d5547c5300cf8162b8f31a40aea6847a5c32?diff=split#diff-7e23eb1aa3b7b4d5db89bfd2860277e5L75")
	exampleCommitFix3, _ := url.Parse("https://github.com/wso2/developer-studio/commit/cfd84b83349e67de4b0239733bc6ed01287856b7?diff=split#diff-645425e844adc2eab8197719cbb2fe8dL285")

	references := []snyk.Reference{
		{Title: "improve logging and testing", Url: exampleCommitFix1},
		{Title: "more tests, exceptions", Url: exampleCommitFix2},
		{Title: "log errors to the log file", Url: exampleCommitFix3},
	}
	return references
}

func Test_getFormattedMessage(t *testing.T) {
	testutil.UnitTest(t)
	_, _, sarifResponse := setupConversionTests(t)
	run := sarifResponse.Sarif.Runs[0]
	result := run.Results[0]

	msg := result.getFormattedMessage(run.getRule("1"))

	assert.Contains(t, msg, "Example Commit Fixes")
	assert.Contains(t, msg, "Data Flow")
}

func TestGetCodeFlowCommands(t *testing.T) {
	testutil.UnitTest(t)
	_, _, sarifResponse := setupConversionTests(t)

	result := sarifResponse.Sarif.Runs[0].Results[0]
	flow := result.getCodeFlow()
	assert.NotEmpty(t, flow)
	assert.Equal(t, snyk.NavigateToRangeCommand, flow[0].toCommand().Command)
}

func setupConversionTests(t *testing.T) (string, []snyk.Issue, SarifResponse) {
	testutil.UnitTest(t)
	temp, err := os.MkdirTemp(xdg.DataHome, "conversionTests")
	if err != nil {
		t.Fatal(t, err, "couldn't create directory for conversion tests")
	}
	path := filepath.Join(temp, "Dummy.java")
	err = os.WriteFile(path, []byte(strings.Repeat("aa\n", 1000)), 0660)
	if err != nil {
		t.Fatal(t, err, "couldn't write test file")
	}
	var analysisResponse SarifResponse
	responseJson := getSarifResponseJson(path)
	err = json.Unmarshal([]byte(responseJson), &analysisResponse)

	if err != nil {
		t.Fatal(t, err, "couldn't unmarshal sarif response")
	}

	issues := analysisResponse.toIssues()
	assert.NotNil(t, issues)
	assert.Equal(t, 2, len(issues))
	return path, issues, analysisResponse
}

func TestSnykCodeBackendService_analysisRequestBody_FillsOrgParameter(t *testing.T) {
	testutil.UnitTest(t)

	// prepare
	config.SetCurrentConfig(config.New())
	org := "test-org"
	config.CurrentConfig().SetOrganization(org)

	analysisOpts := &AnalysisOptions{
		bundleHash: "test-hash",
		shardKey:   "test-key",
		severity:   0,
	}

	expectedRequest := AnalysisRequest{
		Key: AnalysisRequestKey{
			Type:         "file",
			Hash:         analysisOpts.bundleHash,
			LimitToFiles: analysisOpts.limitToFiles,
			Shard:        analysisOpts.shardKey,
		},
		Legacy: false,
		AnalysisContext: AnalysisContext{
			Initiatior: "IDE",
			Flow:       "language-server",
			Org: AnalysisContextOrg{
				Name:        org,
				DisplayName: "unknown",
				PublicId:    "unknown",
			},
		},
	}

	// act
	bytes, err := (&SnykCodeHTTPClient{}).analysisRequestBody(analysisOpts)
	if err != nil {
		assert.Fail(t, "Couldn't obtain analysis request body")
	}

	// assert
	var actualRequest AnalysisRequest
	err = json.Unmarshal(bytes, &actualRequest)
	if err != nil {
		assert.Fail(t, "Couldn't unmarshal analysis request body")
	}

	assert.Equal(t, expectedRequest, actualRequest)
}

func Test_LineChangeChar(t *testing.T) {
	e := exampleCommit{}
	assert.Equal(t, " ", e.lineChangeChar("none"))
	assert.Equal(t, "+", e.lineChangeChar("added"))
	assert.Equal(t, "-", e.lineChangeChar("removed"))
}

func Test_rule_cwe(t *testing.T) {
	t.Run("display CWE if reported", func(t *testing.T) {
		cut := rule{Properties: ruleProperties{
			Cwe: []string{"CWE-23", "CWE-24"},
		}}
		assert.Contains(t, cut.cwe(), "https://cwe.mitre.org/data/definitions/23.html")
		assert.Contains(t, cut.cwe(), "https://cwe.mitre.org/data/definitions/24.html")
	})
	t.Run("dont display CWE if not reported", func(t *testing.T) {
		cut := rule{Properties: ruleProperties{
			Cwe: []string{},
		}}
		assert.NotContains(t, cut.cwe(), "CWE:")
	})
}
