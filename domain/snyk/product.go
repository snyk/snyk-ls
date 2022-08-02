package snyk

import "context"

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
