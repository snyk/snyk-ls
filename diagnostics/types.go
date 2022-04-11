package diagnostics

type ScanLevel int

const (
	ScanFile ScanLevel = iota + 1
	ScanWorkspace
)
