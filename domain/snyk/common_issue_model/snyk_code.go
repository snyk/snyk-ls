/*
 * © 2022 Snyk Limited
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

package common_issue_model

import "time"

type CodeIssue struct {
	Value struct {
		Data struct {
			Id         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				Key                    string `json:"key"`
				Title                  string `json:"title"`
				Type                   string `json:"type"`
				Tool                   string `json:"tool"`
				EffectiveSeverityLevel string `json:"effective_severity_level"`
				Priority               struct {
					Score   int `json:"score"`
					Factors []struct {
						Type  string `json:"type"`
						Score int    `json:"score"`
					} `json:"factors"`
				} `json:"priority"`
				CreatedAt   time.Time `json:"created_at"`
				UpdatedAt   time.Time `json:"updated_at"`
				Description string    `json:"description"`
				Classes     []struct {
					Id     string `json:"id"`
					Source string `json:"source"`
				} `json:"classes"`
				Coordinates []struct {
					Representations []struct {
						File   string `json:"file"`
						Region struct {
							Start struct {
								Line   int `json:"line"`
								Column int `json:"column"`
							} `json:"start"`
							End struct {
								Line   int `json:"line"`
								Column int `json:"column"`
							} `json:"end"`
						} `json:"region"`
					} `json:"representations"`
					Remedies []struct {
						Type        string `json:"type"`
						Description string `json:"description"`
					} `json:"remedies"`
				} `json:"coordinates"`
				Slots struct {
					RuleId  string `json:"rule_id"`
					Message struct {
						Text      string `json:"text"`
						Markdown  string `json:"markdown"`
						Arguments string `json:"arguments"`
					} `json:"message"`
					CodeFlows struct {
						ThreadFlows []struct {
							Locations []struct {
								Location struct {
									Id               int `json:"id"`
									PhysicalLocation struct {
										Region struct {
											StartLine  int `json:"startLine"`
											StartClumn int `json:"startClumn"`
											EndLine    int `json:"endLine"`
											EndClumn   int `json:"endClumn"`
										} `json:"region"`
										ArtifactLocation struct {
											Uri       string `json:"uri"`
											UriBaseId string `json:"uriBaseId"`
										} `json:"artifactLocation"`
									} `json:"physicalLocation"`
								} `json:"location"`
							} `json:"locations"`
						} `json:"threadFlows"`
					} `json:"code_flows"`
					Fingerprint struct {
						Version int    `json:"version"`
						Value   string `json:"value"`
					} `json:"fingerprint"`
				} `json:"slots"`
			} `json:"attributes"`
			Relationships struct {
				Organization struct {
					Data struct {
						Type string `json:"type"`
						Id   string `json:"id"`
					} `json:"data"`
				} `json:"organization"`
				Project struct {
					Data struct {
						Type string `json:"type"`
						Id   string `json:"id"`
					} `json:"data"`
				} `json:"project"`
			} `json:"relationships"`
		} `json:"data"`
		Jsonapi struct {
			Version string `json:"version"`
		} `json:"jsonapi"`
	} `json:"value"`
}
