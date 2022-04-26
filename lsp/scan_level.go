package lsp

type ScanLevel int

const (
	ScanLevelFile ScanLevel = iota + 1
	ScanLevelWorkspace
)
