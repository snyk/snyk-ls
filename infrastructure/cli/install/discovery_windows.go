/*
 * © 2022 Snyk Limited All rights reserved.
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

package install

func (r *Release) downloadURL() string {
	return r.Assets.Windows.URL
}

func (r *Release) checksumURL() string {
	return r.Assets.Windows.ChecksumURL
}

func (r *Release) checksumInfo() string {
	return r.Assets.Windows.ChecksumInfo
}
