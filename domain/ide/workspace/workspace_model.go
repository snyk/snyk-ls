package workspace

import "sync"

type Workspace struct {
	mutex            sync.Mutex
	workspaceFolders map[string]*Folder
}
