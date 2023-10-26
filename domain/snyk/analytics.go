/*
 * © 2023 Snyk Limited
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

package snyk

import "time"

type ScanDoneAnalyticsData struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			DeviceId                      string `json:"deviceId"`
			Application                   string `json:"application"`
			ApplicationVersion            string `json:"application_version"`
			Os                            string `json:"os"`
			Arch                          string `json:"arch"`
			IntegrationName               string `json:"integration_name"`
			IntegrationVersion            string `json:"integration_version"`
			IntegrationEnvironment        string `json:"integration_environment"`
			IntegrationEnvironmentVersion string `json:"integration_environment_version"`
			EventType                     string `json:"event_type"`
			Status                        string `json:"status"`
			ScanType                      string `json:"scan_type"`
			UniqueIssueCount              struct {
				Critical int `json:"critical"`
				High     int `json:"high"`
				Medium   int `json:"medium"`
				Low      int `json:"low"`
			} `json:"unique_issue_count"`
			DurationMs        string    `json:"duration_ms"`
			TimestampFinished time.Time `json:"timestamp_finished"`
		} `json:"attributes"`
	} `json:"data"`
}

func NewScanDoneAnalyticsData() *ScanDoneAnalyticsData {
	panic("not implemented")
}
