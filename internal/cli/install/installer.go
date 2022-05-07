package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/progress"
)

var Mutex = &sync.Mutex{}
var logger = environment.Logger

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

	return i.installRelease(latestRelease, ctx)
}

func (i *Install) installRelease(release *Release, ctx context.Context) (string, error) {
	d := &Downloader{}
	lockFileName, err := createLockFile(ctx, d)
	if err != nil {
		return "", err
	}
	defer func(name string) {
		cleanupLockFile(ctx, name)
	}(lockFileName)

	err = d.Download(ctx, release, false, progress.Channel, progress.CancelProgressChannel)
	if err != nil {
		return "", err
	}

	return i.Find()
}

func (i *Install) Update(ctx context.Context) (bool, error) {
	r := NewCLIRelease()
	latestRelease, err := r.GetLatestRelease(ctx)
	if err != nil {
		return false, err
	}

	return i.updateFromRelease(latestRelease, ctx)
}

func (i *Install) updateFromRelease(r *Release, ctx context.Context) (bool, error) {
	d := &Downloader{}
	lockFileName, err := createLockFile(ctx, d)
	if err != nil {
		return false, err
	}
	defer func(name string) {
		cleanupLockFile(ctx, name)
	}(lockFileName)

	cliDiscovery := Discovery{}
	latestChecksum, err := expectedChecksum(r, &cliDiscovery)
	if err != nil {
		return false, err
	}

	err = compareChecksum(ctx, latestChecksum, environment.CliPath())
	if err == nil {
		// checksum match, no new version available
		return false, nil
	}

	// Carry out the download of the latest release
	err = d.Download(ctx, r, true, progress.Channel, progress.CancelProgressChannel)
	if err != nil {
		// download failed
		return false, err
	}

	err = replaceOutdatedCli(ctx, d, cliDiscovery)
	if err != nil {
		return false, err
	}

	return true, nil
}

func replaceOutdatedCli(ctx context.Context, d *Downloader, cliDiscovery Discovery) error {
	logger.
		WithField("method", "replaceOutdatedCli").
		Info(ctx, "replacing outdated CLI with latest")
	lsPath, err := d.lsPath(ctx)
	if err != nil {
		return err
	}

	outdatedCliFile := filepath.Join(lsPath, cliDiscovery.ExecutableName(false))
	latestCliFile := filepath.Join(lsPath, cliDiscovery.ExecutableName(true))

	if runtime.GOOS == "windows" {
		tildeExecutableName := outdatedCliFile + "~"

		// Cleanup an old executable, if left after previous update.
		// There should be no chance that this is still running due to 4-day update cycle. Any CLI run should be guaranteed to terminate within 4 days.
		if _, err := os.Stat(tildeExecutableName); err == nil {
			err = os.Remove(tildeExecutableName)
			if err != nil {
				logger.
					WithField("method", "replaceOutdatedCli").
					WithError(err).
					Warn(ctx, "couldn't remove old CLI on Windows")
			}
		}

		// Windows allows to rename a running executable even with opened file handle. Another executable can take name of the old executable.
		err = os.Rename(outdatedCliFile, tildeExecutableName)
		if err != nil {
			logger.
				WithField("method", "replaceOutdatedCli").
				WithError(err).
				Warn(ctx, "couldn't rename current CLI on Windows")
			return err
		}
		err = os.Rename(latestCliFile, outdatedCliFile)
		if err != nil {
			logger.
				WithField("method", "replaceOutdatedCli").
				WithError(err).
				Warn(ctx, "couldn't move latest CLI on Windows")
			return err
		}

		// attempt to cleanup the old executable, if scans aren't running at the moment. If errors, the cleanup will happen on the next update
		_ = os.Remove(tildeExecutableName)

		return nil
	}

	// Unix systems keep executable in memory, fine to move.
	err = os.Rename(latestCliFile, outdatedCliFile)
	if err != nil {
		logger.
			WithField("method", "replaceOutdatedCli").
			WithError(err).
			Warn(ctx, "couldn't move latest CLI to replace current CLI")
		return err
	}
	return nil
}

func expectedChecksum(r *Release, cliDiscovery *Discovery) (HashSum, error) {
	checksumInfo, err := cliDiscovery.ChecksumInfo(r)
	if err != nil {
		return nil, err
	}
	line := strings.TrimSpace(checksumInfo)
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return nil, fmt.Errorf("unexpected checksum line format: %q", line)
	}
	h, err := HashSumFromHexDigest(parts[0])
	if err != nil {
		return nil, err
	}
	return h, nil
}

func createLockFile(ctx context.Context, d *Downloader) (lockfileName string, err error) {
	lockFileName, err := d.lockFileName(ctx)
	if err != nil {
		return "", err
	}
	fileInfo, err := os.Stat(lockFileName)
	if err == nil && (time.Since(fileInfo.ModTime()) < 1*time.Hour) {
		msg := fmt.Sprintf("installer lockfile from %v found", fileInfo.ModTime())
		logger.
			WithField("method", "createLockFile").
			WithField("lockfile", lockfileName).
			WithError(err).
			Error(ctx, msg)
		return "", errors.New(msg)
	}
	err = d.createLockFile(ctx)
	if err != nil {
		return "", err
	}
	return lockFileName, nil
}

func cleanupLockFile(ctx context.Context, lockFileName string) {
	err := os.Remove(lockFileName)
	if err != nil {
		logger.
			WithField("method", "cleanupLockFile").
			WithField("lockfile", lockFileName).
			WithError(err).
			Error(ctx, "couldn't clean up lockfile")
	}
}
