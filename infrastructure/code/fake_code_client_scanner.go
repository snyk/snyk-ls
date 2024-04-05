/*
 * © 2024 Snyk Limited
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
	"context"
	"encoding/json"
	"fmt"
	"strings"

	codeClientSarif "github.com/snyk/code-client-go/sarif"
)

type FakeCodeScannerClient struct {
	UploadAndAnalyzeWasCalled bool
	rootPath                  string
}

func getSarifResponseJson2(filePath string) string {
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
                          "lineNumber": 1,
                          "lineChange": "none"
                        },
                        {
                          "line": "  newCopy.read(dis);",
                          "lineNumber": 2,
                          "lineChange": "none"
                        },
                        {
                          "line": "} catch (IOException e) {",
                          "lineNumber": 3,
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
                          "lineNumber": 1,
                          "lineChange": "none"
                        },
                        {
                          "line": "  }",
                          "lineNumber": 2,
                          "lineChange": "none"
                        },
                        {
                          "line": "} catch (InterruptedException e) {",
                          "lineNumber": 3,
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
                              "startLine": 1,
                              "endLine": 2,
                              "startColumn": 1,
                              "endColumn": 4
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
                              "startLine": 2,
                              "endLine": 2,
                              "startColumn": 1,
                              "endColumn": 4
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
						"suppressions": [
							{
								"justification": "False positive",
								"properties": {
									"category": "wont-fix",
									"expiration": "13 days",
									"ignoredOn": "2024-02-23T16:08:25Z",
									"ignoredBy": {
										"name": "Neil M",
										"email": "test@test.io"
									}
								}
							}
						],
            "locations": [
              {
                "physicalLocation": {
                  "artifactLocation": {
                    "uri": "%s",
                    "uriBaseId": "dummy"
                  },
                  "region": {
                    "startLine": 1,
                    "endLine": 2,
                    "startColumn": 1,
                    "endColumn": 5
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
                              "startLine": 1,
                              "endLine": 1,
                              "startColumn": 1,
                              "endColumn": 4
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
`, filePath, filePath, filePath, filePath, filePath)
}

func (f *FakeCodeScannerClient) UploadAndAnalyze(ctx context.Context, requestId string, path string,
	files <-chan string,
	changedFiles map[string]bool) (*codeClientSarif.SarifResponse, string, error) {
	var analysisResponse codeClientSarif.SarifResponse
	responseJson := getSarifResponseJson2(path)
	err := json.Unmarshal([]byte(responseJson), &analysisResponse)
	f.UploadAndAnalyzeWasCalled = true
	return &analysisResponse, "", err
}
