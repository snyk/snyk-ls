package ide

type WorkspaceFolderStatus int
type ProductLine string
type ProductLineAttributes map[string]interface{}

const (
	Unscanned WorkspaceFolderStatus = iota
	Scanned   WorkspaceFolderStatus = iota

	SnykCode       ProductLine = "Snyk Code"
	SnykOpenSource ProductLine = "Snyk Open Source"
	SnykIac        ProductLine = "Snyk IaC"
)

type WorkspaceFolder struct {
	path                  string
	name                  string
	status                WorkspaceFolderStatus
	productLineAttributes map[ProductLine]ProductLineAttributes
}

func (f WorkspaceFolder) GetProductAttribute(productLine ProductLine, name string) interface{} {
	return f.productLineAttributes[productLine][name]
}

func (f *WorkspaceFolder) AddProductAttribute(productLine ProductLine, name string, value interface{}) {
	f.productLineAttributes[productLine][name] = value
}

func NewWorkspaceFolder(path string, name string) WorkspaceFolder {
	folder := WorkspaceFolder{
		path:                  path,
		name:                  name,
		status:                Unscanned,
		productLineAttributes: make(map[ProductLine]ProductLineAttributes),
	}
	folder.productLineAttributes[SnykCode] = ProductLineAttributes{}
	folder.productLineAttributes[SnykIac] = ProductLineAttributes{}
	folder.productLineAttributes[SnykOpenSource] = ProductLineAttributes{}
	return folder
}
