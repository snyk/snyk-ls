package snyk

import "context"

// type Filepath string
// See if we can have an interface with a single property Target that can be either a folder or a file. If not, we use ScanTarget as an interface with Target being folder or file and WorkspaceFolder always being a folder to satisfy different product requirements, e.g. OSS & Code.
// type ScanTarget interface {
// 	Target Filepath, // see if folder / file
// 	// WorkspaceFolder Filepath, // which is string
// }

type ProductScanner interface {
	// Scans a workspace folder or file for issues, given its path. 'folderPath' provides a path to a workspace folder, if a file needs to be scanned.
	Scan(
		//todo do we need context?
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

func NewTestProductScanner(product Product, enabled bool) *TestProductScanner {
	return &TestProductScanner{
		product: product,
		enabled: enabled,
		Scans:   0,
	}
}

type TestProductScanner struct {
	product Product
	enabled bool
	Scans   int
}

func (t *TestProductScanner) Scan(_ context.Context, _ string, _ string) (issues []Issue) {
	t.Scans++
	return []Issue{}
}

func (t *TestProductScanner) IsEnabled() bool {
	return t.enabled
}

func (t *TestProductScanner) Product() Product {
	return t.product
}
