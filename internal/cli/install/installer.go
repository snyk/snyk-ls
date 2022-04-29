package install

import (
	"context"
	"sync"
)

var Mutex = &sync.Mutex{}

type Installer interface {
	Find() (string, error)
	Install(ctx context.Context) (string, error)
}

type Install struct{}

func NewInstaller() *Install {
	return &Install{}
}

func (i *Install) Find() (string, error) {
	d := &Discovery{}
	execPath, _ := d.LookUserDir()
	if execPath != "" {
		return execPath, nil
	}
	execPath, err := d.LookPath()
	if err != nil {
		return "", err
	}
	return execPath, nil
}

func (i *Install) Install(ctx context.Context) (string, error) {
	r := NewCLIRelease()
	latestRelease, err := r.GetLatestRelease(ctx)
	if err != nil {
		return "", err
	}

	d := &Downloader{}
	err = d.Download(latestRelease)
	if err != nil {
		return "", err
	}

	return i.Find()
}
