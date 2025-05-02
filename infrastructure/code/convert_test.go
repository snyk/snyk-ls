/*
 * © 2022-2025 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package code

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	codeClientSarif "github.com/snyk/code-client-go/sarif"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func getSarifResponseJson(filePath types.FilePath) string {
	filePath = types.FilePath(strings.ReplaceAll(string(filePath), `\`, `\\`))
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
      "lang": "DIGITAL CommandData Language"
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
							"markdown": "Printing the stack trace of {0}. Production code should not use {1}. {2}",
							"arguments": [
								"[java.lang.InterruptedException](0)",
								"[printStackTrace](1)(2)",
								"[This is a test argument](3)"
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
                      },
											{
												"location": {
                          "id": 2,
                          "physicalLocation": {
                            "artifactLocation": {
																"uri": "%s",
                              "uriBaseId": "dummy"
                            },
                            "region": {
                              "startLine": 10,
                              "endLine": 10,
                              "startColumn": 10,
                              "endColumn": 10
                            }
                          }
                        }
											},
											{
												"location": {
                          "id": 3,
                          "physicalLocation": {
                            "artifactLocation": {
																"uri": "%s",
                              "uriBaseId": "dummy"
                            },
                            "region": {
                              "startLine": 20,
                              "endLine": 20,
                              "startColumn": 20,
                              "endColumn": 20
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
              "lang": "DIGITAL CommandData Language"
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
`, filePath, filePath, filePath, filePath, filePath, filePath, filePath)
}

func TestSnykCodeBackendService_convert_shouldConvertIssues(t *testing.T) {
	filePath, issues, resp := setupConversionTests(t, true, true)
	issueDescriptionURL, _ := url.Parse(codeDescriptionURL)
	references := referencesForSampleSarifResponse()

	issue := issues[0]
	codeIssueData := issue.GetAdditionalData().(snyk.CodeIssueData)

	assert.Equal(t,
		"DontUsePrintStackTrace: Printing the stack trace of java.lang.InterruptedException. Production code ...",
		issue.GetMessage())
	assert.Equal(t, types.CodeQualityIssue, issue.GetIssueType())
	assert.Equal(t, types.Low, issue.GetSeverity())
	assert.Equal(t, types.FilePath(filePath), issue.GetAffectedFilePath())
	assert.Equal(t, types.Range{Start: types.Position{Line: 5, Character: 6}, End: types.Position{Line: 5, Character: 6}}, issue.GetRange())
	assert.Equal(t, product.ProductCode, issue.GetProduct())
	assert.Equal(t, issueDescriptionURL, issue.GetIssueDescriptionURL())
	assert.Equal(t, references, issue.GetReferences())
	assert.Contains(t, issue.GetFormattedMessage(), "Example Commit Fixes")
	assert.Equal(t, markersForSampleSarifResponse(filePath), codeIssueData.Markers)
	assert.Equal(t, 550, codeIssueData.PriorityScore)
	assert.Equal(t, resp.Sarif.Runs[0].Tool.Driver.Rules[0].Properties.Cwe, issue.GetCWEs())
	assert.Nil(t, issue.GetIgnoreDetails())
	assert.False(t, issue.GetIsIgnored())
	dataFlow := codeIssueData.DataFlow
	assert.Equal(t, issue.GetAffectedFilePath(), dataFlow[0].FilePath)
	assert.Equal(t, issue.GetAffectedFilePath(), dataFlow[1].FilePath)
	assert.Equal(t, issue.GetAffectedFilePath(), dataFlow[2].FilePath)
	assert.Equal(t, issue.GetAffectedFilePath(), dataFlow[3].FilePath)
}

func referencesForSampleSarifResponse() []types.Reference {
	exampleCommitFix1, _ := url.Parse("https://github.com/apache/flink/commit/5d7c5620804eddd59206b24c87ffc89c12fd1184?diff=split#diff-86ec3e3884662ba3b5f4bb5050221fd6L94")
	exampleCommitFix2, _ := url.Parse("https://github.com/rtr-nettest/open-rmbt/commit/0fa9d5547c5300cf8162b8f31a40aea6847a5c32?diff=split#diff-7e23eb1aa3b7b4d5db89bfd2860277e5L75")
	exampleCommitFix3, _ := url.Parse("https://github.com/wso2/developer-studio/commit/cfd84b83349e67de4b0239733bc6ed01287856b7?diff=split#diff-645425e844adc2eab8197719cbb2fe8dL285")

	references := []types.Reference{
		{Title: "improve logging and testing", Url: exampleCommitFix1},
		{Title: "more tests, exceptions", Url: exampleCommitFix2},
		{Title: "log errors to the log file", Url: exampleCommitFix3},
	}
	return references
}

func markersForSampleSarifResponse(path string) []snyk.Marker {
	references := []snyk.Marker{
		{
			Msg: [2]int{28, 57},
			Pos: []snyk.MarkerPosition{
				{
					Rows: [2]int{4, 4},
					Cols: [2]int{13, 33},
					File: path,
				},
			},
		},
		{
			Msg: [2]int{91, 105},
			Pos: []snyk.MarkerPosition{
				{
					Rows: [2]int{5, 5},
					Cols: [2]int{8, 23},
					File: path,
				},
				{
					Rows: [2]int{9, 9},
					Cols: [2]int{9, 10},
					File: path,
				},
			},
		},
		{
			Msg: [2]int{108, 130},
			Pos: []snyk.MarkerPosition{
				{
					Rows: [2]int{19, 19},
					Cols: [2]int{19, 20},
					File: path,
				},
			},
		},
	}

	return references
}

func Test_getFormattedMessage(t *testing.T) {
	c := testutil.UnitTest(t)
	p, _, sarifResponse := setupConversionTests(t, true, true)
	run := sarifResponse.Sarif.Runs[0]
	testResult := run.Results[0]

	sarifConverter := SarifConverter{sarif: sarifResponse, c: c}
	msg := sarifConverter.formattedMessageMarkdown(testResult, sarifConverter.getRule(run, "1"), types.FilePath(filepath.Dir(p)))

	assert.Contains(t, msg, "Example Commit Fixes")
	assert.Contains(t, msg, "Data Flow")
}

func setupConversionTests(t *testing.T,
	activateSnykCodeSecurity bool,
	activateSnykCodeQuality bool,
) (path string, issues []types.Issue, response codeClientSarif.SarifResponse) {
	t.Helper()
	testutil.UnitTest(t)
	c := config.CurrentConfig()
	c.EnableSnykCodeSecurity(activateSnykCodeSecurity)
	c.EnableSnykCodeQuality(activateSnykCodeQuality)
	temp := types.FilePath(t.TempDir())
	path = filepath.Join(string(temp), "File With Spaces.java")
	err := os.WriteFile(path, []byte(strings.Repeat("aa\n", 1000)), 0660)
	if err != nil {
		t.Fatal(err, "couldn't write test file")
	}

	relPath, err := ToRelativeUnixPath(temp, types.FilePath(path))
	encodedPath := EncodePath(relPath)
	if err != nil {
		t.Fatal(err, "couldn't get relative path")
	}

	var analysisResponse codeClientSarif.SarifResponse
	responseJson := getSarifResponseJson(encodedPath)
	err = json.Unmarshal([]byte(responseJson), &analysisResponse)

	sarifConverter := SarifConverter{sarif: analysisResponse, c: c}

	if err != nil {
		t.Fatal(err, "couldn't unmarshal sarif response")
	}

	issues, err = sarifConverter.toIssues(temp)
	assert.Nil(t, err)

	return path, issues, analysisResponse
}

func TestSnykCodeBackendService_analysisRequestBodyIsCorrect(t *testing.T) {
	testutil.UnitTest(t)

	// prepare
	config.SetCurrentConfig(config.New())
	org := "00000000-0000-0000-0000-000000000023"
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
		Legacy:          false,
		AnalysisContext: newCodeRequestContext(),
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
	t.Run("display CWEs if reported", func(t *testing.T) {
		cut := codeClientSarif.Rule{Properties: codeClientSarif.RuleProperties{
			Cwe: []string{"CWE-23", "CWE-24"},
		}}
		sarifConverter := SarifConverter{sarif: codeClientSarif.SarifResponse{}}
		assert.Contains(t, sarifConverter.cwe(cut), "https://cwe.mitre.org/data/definitions/23.html")
		assert.Contains(t, sarifConverter.cwe(cut), "https://cwe.mitre.org/data/definitions/24.html")
	})
	t.Run("dont display CWEs if not reported", func(t *testing.T) {
		cut := codeClientSarif.Rule{Properties: codeClientSarif.RuleProperties{
			Cwe: []string{},
		}}
		sarifConverter := SarifConverter{sarif: codeClientSarif.SarifResponse{}}
		assert.NotContains(t, sarifConverter.cwe(cut), "CWE:")
	})
}

func Test_getCodeIssueType(t *testing.T) {
	t.Run("Security issue - single category", func(t *testing.T) {
		testRule := codeClientSarif.Rule{
			Properties: codeClientSarif.RuleProperties{
				Categories: []string{"Security"},
			},
		}

		sarifConverter := SarifConverter{sarif: codeClientSarif.SarifResponse{}}
		sarifConverter.getCodeIssueType(testRule)
		assert.Equal(t, types.CodeSecurityVulnerability, sarifConverter.getCodeIssueType(testRule))
	})

	t.Run("Security issue - multiple categories", func(t *testing.T) {
		testRule := codeClientSarif.Rule{
			Properties: codeClientSarif.RuleProperties{
				Categories: []string{"Security", "Defect"},
			},
		}

		sarifConverter := SarifConverter{sarif: codeClientSarif.SarifResponse{}}
		sarifConverter.getCodeIssueType(testRule)
		assert.Equal(t, types.CodeSecurityVulnerability, sarifConverter.getCodeIssueType(testRule))
	})

	t.Run("Quality - single category", func(t *testing.T) {
		testRule := codeClientSarif.Rule{
			Properties: codeClientSarif.RuleProperties{
				Categories: []string{"Defect"},
			},
		}

		sarifConverter := SarifConverter{sarif: codeClientSarif.SarifResponse{}}
		sarifConverter.getCodeIssueType(testRule)
		assert.Equal(t, types.CodeQualityIssue, sarifConverter.getCodeIssueType(testRule))
	})

	t.Run("Quality - multiple categories", func(t *testing.T) {
		testRule := codeClientSarif.Rule{
			Properties: codeClientSarif.RuleProperties{
				Categories: []string{"Defect", "Info"},
			},
		}

		sarifConverter := SarifConverter{sarif: codeClientSarif.SarifResponse{}}
		sarifConverter.getCodeIssueType(testRule)
		assert.Equal(t, types.CodeQualityIssue, sarifConverter.getCodeIssueType(testRule))
	})
}

func Test_AutofixResponse_toUnifiedDiffSuggestions(t *testing.T) {
	response := AutofixResponse{
		Status: "COMPLETE",
	}
	fixes := []autofixResponseSingleFix{{
		Id:    "123e4567-e89b-12d3-a456-426614174000/1",
		Value: "var x = [];",
	}}
	response.AutofixSuggestions = append(response.AutofixSuggestions, fixes...)
	filePath := "file.js"
	baseDir := types.FilePath(t.TempDir())
	err := os.WriteFile(filepath.Join(string(baseDir), filePath), []byte("var x = new Array();"), 0666)
	require.NoError(t, err)
	unifiedDiffSuggestions := response.toUnifiedDiffSuggestions(baseDir, types.FilePath(filePath))

	assert.Equal(t, len(unifiedDiffSuggestions), 1)
	assert.Equal(t, unifiedDiffSuggestions[0].FixId, "123e4567-e89b-12d3-a456-426614174000/1")
	assert.NotEqual(t, len(unifiedDiffSuggestions[0].UnifiedDiffsPerFile), 0)
}

func Test_AutofixResponse_toUnifiedDiffSuggestions_HtmlEncodedFilePath(t *testing.T) {
	response := AutofixResponse{
		Status: "COMPLETE",
	}
	fixes := []autofixResponseSingleFix{{
		Id:    "123e4567-e89b-12d3-a456-426614174000/1",
		Value: "var x = [];",
	}}
	response.AutofixSuggestions = append(response.AutofixSuggestions, fixes...)
	filePath := "file_with space.js"
	baseDir := types.FilePath(t.TempDir())
	err := os.WriteFile(filepath.Join(string(baseDir), filePath), []byte("var x = new Array();"), 0666)
	require.NoError(t, err)
	// Here we provide the HTML encoded path and it should be decoded in the function to read the correct file.
	unifiedDiffSuggestions := response.toUnifiedDiffSuggestions(baseDir, "file_with%20space.js")

	assert.Equal(t, len(unifiedDiffSuggestions), 1)
	assert.Equal(t, unifiedDiffSuggestions[0].FixId, "123e4567-e89b-12d3-a456-426614174000/1")
	assert.NotEqual(t, len(unifiedDiffSuggestions[0].UnifiedDiffsPerFile), 0)
}

func Test_Result_getMarkers_basic(t *testing.T) {
	r := codeClientSarif.Result{
		Message: codeClientSarif.ResultMessage{
			Text:     "",
			Markdown: "Printing the stack trace of {0}. Production code should not use {1}. {3}",
			Arguments: []string{"[java.lang.InterruptedException](0)", "[printStackTrace](1)(2)", "",
				"[This is a test argument](3)"},
		},
	}

	sarifConverter := SarifConverter{sarif: codeClientSarif.SarifResponse{}}
	marker, err := sarifConverter.getMarkers(r, "")
	assert.Nil(t, err)
	assert.Len(t, marker, 3)
}

func Test_Result_getIgnoreDetails(t *testing.T) {
	t.Run("does not return ignore details if no suppressions", func(t *testing.T) {
		r := codeClientSarif.Result{
			Message: codeClientSarif.ResultMessage{
				Text:     "",
				Markdown: "Printing the stack trace of {0}. Production code should not use {1}. {3}",
				Arguments: []string{"[java.lang.InterruptedException](0)", "[printStackTrace](1)(2)", "",
					"[This is a test argument](3)"},
			},
		}

		isIgnored, ignoreDetails := GetIgnoreDetailsFromSuppressions(r.Suppressions)
		assert.False(t, isIgnored)
		assert.Nil(t, ignoreDetails)
	})

	t.Run("does return ignore details if one suppression", func(t *testing.T) {
		expiration := "2024-08-06T13:16:53Z"
		r := codeClientSarif.Result{
			Message: codeClientSarif.ResultMessage{
				Text:     "",
				Markdown: "Printing the stack trace of {0}. Production code should not use {1}. {3}",
				Arguments: []string{"[java.lang.InterruptedException](0)", "[printStackTrace](1)(2)", "",
					"[This is a test argument](3)"},
			},
			Suppressions: []codeClientSarif.Suppression{
				{
					Justification: "reason",
					Properties: codeClientSarif.SuppressionProperties{
						Category:   "category",
						Expiration: &expiration,
						IgnoredOn:  "2024-02-23T16:08:25Z",
						IgnoredBy: codeClientSarif.IgnoredBy{
							Name: "name",
						},
					},
				},
			},
		}

		isIgnored, ignoreDetails := GetIgnoreDetailsFromSuppressions(r.Suppressions)
		assert.True(t, isIgnored)
		assert.NotNil(t, ignoreDetails)
		assert.Equal(t, "reason", ignoreDetails.Reason)
		assert.Equal(t, "category", ignoreDetails.Category)
		assert.Equal(t, expiration, ignoreDetails.Expiration)
		assert.Equal(t, 2024, ignoreDetails.IgnoredOn.Year())
		assert.Equal(t, "name", ignoreDetails.IgnoredBy)
	})

	t.Run("sets reason to a default value if justification not provided in suppression", func(t *testing.T) {
		expiration := "2024-08-06T13:16:53Z"
		r := codeClientSarif.Result{
			Message: codeClientSarif.ResultMessage{
				Text:     "",
				Markdown: "Printing the stack trace of {0}. Production code should not use {1}. {3}",
				Arguments: []string{"[java.lang.InterruptedException](0)", "[printStackTrace](1)(2)", "",
					"[This is a test argument](3)"},
			},
			Suppressions: []codeClientSarif.Suppression{
				{
					Properties: codeClientSarif.SuppressionProperties{
						Category:   "category",
						Expiration: &expiration,
						IgnoredOn:  "2024-02-23T16:08:25Z",
						IgnoredBy: codeClientSarif.IgnoredBy{
							Name: "name",
						},
					},
				},
			},
		}

		isIgnored, ignoreDetails := GetIgnoreDetailsFromSuppressions(r.Suppressions)
		assert.True(t, isIgnored)
		assert.NotNil(t, ignoreDetails)
		assert.Equal(t, "None given", ignoreDetails.Reason)
		assert.Equal(t, "category", ignoreDetails.Category)
		assert.Equal(t, expiration, ignoreDetails.Expiration)
		assert.Equal(t, 2024, ignoreDetails.IgnoredOn.Year())
		assert.Equal(t, "name", ignoreDetails.IgnoredBy)
	})
}

func Test_ParseDateFromString(t *testing.T) {
	today := time.Now().UTC()

	type testCase struct {
		name string
		date string
		want time.Time
	}

	tests := []testCase{
		{
			name: "accepted date format",
			date: "Wed Jun 05 2024",
			want: time.Date(2024, time.June, 5, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "valid RFC3339 format",
			date: "2024-02-23T16:08:25Z",
			want: time.Date(2024, time.February, 23, 16, 8, 25, 0, time.UTC),
		},
		{
			name: "invalid date format",
			date: "Jun 05 2024 Wednesday",
			want: today, // Only assert day, month, and year
		},
		{
			name: "invalid date format: empty date",
			date: "",
			want: today, // Only assert day, month, and year
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDateFromString(tt.date)
			if strings.Contains(tt.name, "invalid date format") {
				if got.Year() != today.Year() || got.Month() != today.Month() || got.Day() != today.Day() {
					t.Errorf("Expected today's date: %v, but got %v", today, got)
				}
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestCreateAutofixWorkspaceEdit(t *testing.T) {
	testDataDirPath := "testdata/convert_test/TestCreateAutofixWorkspaceEdit"

	tests := []struct {
		name             string
		originalFilePath string
		diffFilePath     string
		// Either set:
		expectedEdits []types.TextEdit
		// or set:
		expectedErrorMsgRegex *string
	}{
		{
			name:             "Multi-hunk diff results in grouped TextEdits",
			originalFilePath: path.Join(testDataDirPath, "01_simple/base_simple_file.txt"),
			diffFilePath:     path.Join(testDataDirPath, "01_simple/good_diff_01.patch"),
			expectedEdits: []types.TextEdit{
				// Hunk 1: The two deletions and one addition are combined into a single replacement edit.
				// Replaces lines 2 and 3 (0-based) with "three\n".
				{
					Range: types.Range{
						// Start at the beginning of the first deleted line (line 2, 0-based)
						Start: types.Position{Line: 2, Character: 0},
						// End *after* the last deleted line (line 3, 0-based).
						// End line = Start Line (2) + number of deleted lines (2) = 4
						End: types.Position{Line: 4, Character: 0},
					},
					// The replacement text from the '+' line(s)
					NewText: "three\n",
				},
				// Hunk 2: The two additions are combined into a single insertion edit.
				// Inserts "six\nseven\n" before original line 6 (0-based index 5).
				{
					Range: types.Range{
						// Start and End position are the same for an insertion.
						// It inserts before the line where "eight" was originally (line 6, 0-based index 5).
						// The original lines corresponding to the start of Hunk 2 are:
						// line 4 (index 3): "four"
						// line 5 (index 4): "five"
						// Insertion happens *before* the next original line ("eight"), which was line 6 (index 5).
						Start: types.Position{Line: 5, Character: 0},
						End:   types.Position{Line: 5, Character: 0},
					},
					// The combined text from the '+' lines
					NewText: "six\nseven\n",
				},
			},
		},
		{
			name:                  "Malformed diff causes parse error",
			originalFilePath:      path.Join(testDataDirPath, "01_simple/base_simple_file.txt"),
			diffFilePath:          path.Join(testDataDirPath, "01_simple/malformed_diff_01.patch"),
			expectedErrorMsgRegex: util.Ptr("^failed to parse file diff: .+$"),
		},
		{
			name:                  "Short file causes processing error",
			originalFilePath:      path.Join(testDataDirPath, "01_simple/corrupt_short_file.txt"),
			diffFilePath:          path.Join(testDataDirPath, "01_simple/good_diff_01.patch"),
			expectedErrorMsgRegex: util.Ptr("^error processing hunk 0 for .+: hunk applies changes up to line 5 but file only has 2 lines$"),
		},
		{
			name:                  "Missing file causes error",
			originalFilePath:      "/this/file/does/not/exist",
			diffFilePath:          path.Join(testDataDirPath, "01_simple/good_diff_01.patch"), // The file content is irrelevant, but must the file must exist
			expectedErrorMsgRegex: util.Ptr("^failed to read file /this/file/does/not/exist for validation: open /this/file/does/not/exist: no such file or directory$"),
		},
		{
			name:             "Complex diff produces the correct edits",
			originalFilePath: path.Join(testDataDirPath, "02_real_js/base_real_js.js"),
			diffFilePath:     path.Join(testDataDirPath, "02_real_js/good_diff_01.patch"),
			expectedEdits: []types.TextEdit{
				{
					Range: types.Range{
						Start: types.Position{
							Line:      2,
							Character: 0,
						},
						End: types.Position{
							Line:      2,
							Character: 0,
						},
					},
					NewText: "const sanitize = require('sanitize-filename');\n",
				},
				{
					Range: types.Range{
						Start: types.Position{
							Line:      5,
							Character: 0,
						},
						End: types.Position{
							Line:      6,
							Character: 0,
						},
					},
					NewText: "  const filename = sanitize(req.params.filename);\n",
				},
				{
					Range: types.Range{
						Start: types.Position{
							Line:      10,
							Character: 0,
						},
						End: types.Position{
							Line:      11,
							Character: 0,
						},
					},
					NewText: "      res.download(path.basename(filePath));\n",
				},
			},
		},
		{
			name:             "Complex multi-hunk diff with swaps and deletions",
			originalFilePath: path.Join(testDataDirPath, "03_complex_example/base_file.txt"),
			diffFilePath:     path.Join(testDataDirPath, "03_complex_example/good_diff_01.patch"),
			expectedEdits: []types.TextEdit{
				// - Hunk 1 -
				// Delete "3  -> X  - Delete"
				{
					Range: types.Range{
						Start: types.Position{Line: 2, Character: 0},
						End:   types.Position{Line: 3, Character: 0},
					},
					NewText: "",
				},
				// - Hunk 2 -
				// Delete "14 -> X  - Delete"
				{
					Range: types.Range{
						Start: types.Position{Line: 13, Character: 0},
						End:   types.Position{Line: 14, Character: 0},
					},
					NewText: "",
				},
				// Delete "16 -> 15 - Swap with below"
				{
					Range: types.Range{
						Start: types.Position{Line: 15, Character: 0},
						End:   types.Position{Line: 16, Character: 0},
					},
					NewText: "",
				},
				// Insert "16 -> 15 - Swap with below"
				{
					Range: types.Range{
						Start: types.Position{Line: 17, Character: 0},
						End:   types.Position{Line: 17, Character: 0},
					},
					NewText: "16 -> 15 - Swap with below\n",
				},
				// Delete "19 -> X  - Delete"
				{
					Range: types.Range{
						Start: types.Position{Line: 18, Character: 0},
						End:   types.Position{Line: 19, Character: 0},
					},
					NewText: "",
				},
				// Insert "X  -> 18 - Added"
				// Insert "X  -> 19 - Added"
				{
					Range: types.Range{
						Start: types.Position{Line: 20, Character: 0},
						End:   types.Position{Line: 20, Character: 0},
					},
					NewText: "X  -> 18 - Added\nX  -> 19 - Added\n",
				},
			},
		},
		{
			name:             "Complex single-hunk diff with more deletions than additions",
			originalFilePath: path.Join(testDataDirPath, "04_another_complex/base_file.txt"),
			diffFilePath:     path.Join(testDataDirPath, "04_another_complex/good_diff_01.patch"),
			expectedEdits: []types.TextEdit{
				// Insert "X  -> 3  - Added"
				{
					Range: types.Range{
						Start: types.Position{Line: 2, Character: 0},
						End:   types.Position{Line: 2, Character: 0},
					},
					NewText: "X  -> 3  - Added\n",
				},
				// Delete "5  -> X  - Delete"
				// Insert "X  -> 6  - Added"
				// Insert "X  -> 7  - Added"
				{
					Range: types.Range{
						Start: types.Position{Line: 4, Character: 0},
						End:   types.Position{Line: 5, Character: 0},
					},
					NewText: "X  -> 6  - Added\nX  -> 7  - Added\n",
				},
				// Insert "X  -> 13 - Added"
				// Insert "X  -> 14 - Added"
				{
					Range: types.Range{
						Start: types.Position{Line: 10, Character: 0},
						End:   types.Position{Line: 10, Character: 0},
					},
					NewText: "X  -> 13 - Added\nX  -> 14 - Added\n",
				},
				// Delete "13 -> X  - Delete"
				{
					Range: types.Range{
						Start: types.Position{Line: 12, Character: 0},
						End:   types.Position{Line: 13, Character: 0},
					},
					NewText: "",
				},
				// Insert "X  -> 18 - Added"
				// Insert "X  -> 19 - Added"
				{
					Range: types.Range{
						Start: types.Position{Line: 14, Character: 0},
						End:   types.Position{Line: 14, Character: 0},
					},
					NewText: "X  -> 18 - Added\nX  -> 19 - Added\n",
				},
				// Delete "19 -> X  - Delete"
				{
					Range: types.Range{
						Start: types.Position{Line: 18, Character: 0},
						End:   types.Position{Line: 19, Character: 0},
					},
					NewText: "",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Read the diff file
			diffBytes, err := os.ReadFile(tt.diffFilePath)
			require.NoError(t, err)
			diff := string(diffBytes)

			// Create a WorkSpaceEdit for the file, and check against the reference.
			actualWorkspaceEdit, err := CreateWorkspaceEditFromDiff(config.CurrentConfig().Logger(), tt.originalFilePath, diff)
			if tt.expectedErrorMsgRegex != nil {
				assert.Nil(t, actualWorkspaceEdit)
				require.Error(t, err)
				assert.Regexp(t, *tt.expectedErrorMsgRegex, err.Error())
			} else if tt.expectedEdits != nil {
				assert.NoError(t, err)
				require.NotNil(t, actualWorkspaceEdit)
				require.Contains(t, actualWorkspaceEdit.Changes, tt.originalFilePath)
				assert.Equal(t, tt.expectedEdits, actualWorkspaceEdit.Changes[tt.originalFilePath])
			} else {
				assert.Fail(t, "Bad test case, no expected error message or expected edits")
			}
		})
	}
}
