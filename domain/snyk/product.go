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
