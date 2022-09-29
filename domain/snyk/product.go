/*
 * Copyright 2022 Snyk Ltd.
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

import (
	"context"
)

// type Filepath string
// See if we can have an interface with a single property Target that can be either a folder or a file. If not, we use ScanTarget as an interface with Target being folder or file and WorkspaceFolder always being a folder to satisfy different product requirements, e.g. OSS & Code.
// type ScanTarget interface {
// 	Target Filepath, // see if folder / file
// 	// WorkspaceFolder Filepath, // which is string
// }

type ProductScanner interface {
	// Scan scans a workspace folder or file for issues, given its path. 'folderPath' provides a path to a workspace folder, if a file needs to be scanned.
	Scan(
		ctx context.Context,
		path string,
		folderPath string,
	) (issues []Issue)

	IsEnabled() bool
	Product() Product
}
type Product string
type ProductAttributes map[string]interface{}

const (
	ProductCode                 Product = "Snyk Code"
	ProductOpenSource           Product = "Snyk Open Source"
	ProductInfrastructureAsCode Product = "Snyk IaC"
)
