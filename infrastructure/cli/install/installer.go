/*
 * © 2022 Snyk Limited All rights reserved.
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

package install

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
)

type Installer interface {
	Find() (string, error)
	Install(ctx context.Context) (string, error)
	Update(ctx context.Context) (bool, error)
}

type Install struct {
	errorReporter error_reporting.ErrorReporter
	httpClient    func() *http.Client
}

func NewInstaller(errorReporter error_reporting.ErrorReporter, client func() *http.Client) *Install {
	return &Install{
		errorReporter: errorReporter,
		httpClient:    client,
	}
}

func (i *Install) Find() (string, error) {
	d := &Discovery{}
	execPath, _ := d.LookConfigPath()
	if execPath != "" {
		return execPath, nil
	}
	execPath, _ = d.LookUserDir()
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
	r := NewCLIRelease(i.httpClient)
	latestRelease, err := r.GetLatestRelease(ctx)
	if err != nil {
		return "", err
	}

	return i.installRelease(latestRelease)
}

func (i *Install) installRelease(release *Release) (string, error) {
	d := NewDownloader(i.errorReporter, i.httpClient)
	lockFileName, err := createLockFile(d)
	if err != nil {
		return "", err
	}
	defer func(name string) { cleanupLockFile(name) }(lockFileName)

	err = d.Download(release, false)
	if err != nil {
		return "", err
	}

	return i.Find()
}

func (i *Install) Update(ctx context.Context) (bool, error) {
	r := NewCLIRelease(i.httpClient)
	latestRelease, err := r.GetLatestRelease(ctx)
	if err != nil {
		return false, err
	}

	return i.updateFromRelease(latestRelease)
}

func (i *Install) updateFromRelease(r *Release) (bool, error) {
	d := NewDownloader(i.errorReporter, i.httpClient)
	lockFileName, err := createLockFile(d)
	if err != nil {
		return false, err
	}
	defer func(name string) { cleanupLockFile(name) }(lockFileName)

	cliDiscovery := Discovery{}
	latestChecksum, err := expectedChecksum(r, &cliDiscovery)
	if err != nil {
		return false, err
	}

	err = compareChecksum(latestChecksum, config.CurrentConfig().CliSettings().Path())
	if err == nil {
		// checksum match, no new version available
		return false, nil
	}

	// Carry out the download of the latest release
	err = d.Download(r, true)
	if err != nil {
		// download failed
		return false, err
	}

	err = replaceOutdatedCli(cliDiscovery)
	if err != nil {
		return false, err
	}

	return true, nil
}

func replaceOutdatedCli(cliDiscovery Discovery) error {
	log.Info().Str("method", "replaceOutdatedCli").Msg("replacing outdated CLI with latest")

	cliPath := config.CurrentConfig().CliSettings().Path()
	latestCliFile := filepath.Join(filepath.Dir(cliPath), cliDiscovery.ExecutableName(true))

	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		tildeExecutableName := cliPath + "~"

		// Cleanup an old executable, if left after previous update.
		// There should be no chance that this is still running due to 4-day update cycle. Any CLI run should be guaranteed to terminate within 4 days.
		if _, err := os.Lstat(tildeExecutableName); err == nil {
			err = os.Remove(tildeExecutableName)
			if err != nil {
				log.Warn().Err(err).Str("method", "replaceOutdatedCli").Msg("couldn't remove old CLI on Windows")
			}
		}

		// Windows allows to rename a running executable even with opened file handle. Another executable can take name of the old executable.
		err := os.Rename(cliPath, tildeExecutableName)
		if err != nil {
			log.Warn().Err(err).Str("method", "replaceOutdatedCli").Msg("couldn't rename current CLI on Windows")
			return err
		}
		err = os.Rename(latestCliFile, cliPath)
		if err != nil {
			log.Warn().Err(err).Str("method", "replaceOutdatedCli").Msg("couldn't move latest CLI on Windows")
			return err
		}

		// attempt to cleanup the old executable, if scans aren't running at the moment. If errors, the cleanup will happen on the next update
		_ = os.Remove(tildeExecutableName)

		return nil
	}

	// Unix systems keep executable in memory, fine to move.
	err := os.Rename(latestCliFile, cliPath)
	if err != nil {
		log.Warn().Err(err).Str("method", "replaceOutdatedCli").Msg("couldn't move latest CLI to replace current CLI")
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

func createLockFile(d *Downloader) (lockfileName string, err error) {
	lockFileName := config.CurrentConfig().CLIDownloadLockFileName()
	fileInfo, err := os.Stat(lockFileName)
	if err == nil && (time.Since(fileInfo.ModTime()) < 10*time.Minute) {
		msg := fmt.Sprintf("installer lockfile from %v found", fileInfo.ModTime())
		log.Error().Str("method", "Download").Str("lockfile", lockFileName).Msg(msg)
		return "", errors.New(msg)
	}
	err = d.createLockFile()
	if err != nil {
		return "", err
	}
	return lockFileName, nil
}

func cleanupLockFile(lockFileName string) {
	file, _ := os.Open(lockFileName)
	_ = file.Close()
	err := os.Remove(lockFileName)
	if err != nil {
		log.Error().Str("method", "Download").Str("lockfile", lockFileName).Msg("couldn't clean up lockfile")
	}
}

type FakeInstaller struct {
	updates  int
	installs int
	mutex    sync.Mutex
}

func (t *FakeInstaller) Updates() int {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return t.updates
}

func (t *FakeInstaller) Installs() int {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return t.installs
}

func (t *FakeInstaller) Find() (string, error) {
	return "", nil
}

func (t *FakeInstaller) Install(_ context.Context) (string, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	path := config.CurrentConfig().CliSettings().Path()
	log.Debug().Msgf("Installing fake 4-byte CLI to %s", path)
	err := os.WriteFile(path, []byte("fake"), 0755)
	if err != nil {
		return "", err
	}

	t.installs++
	return "", nil
}

func (t *FakeInstaller) Update(_ context.Context) (bool, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.updates++
	return true, nil
}

func NewFakeInstaller() *FakeInstaller {
	return &FakeInstaller{
		mutex: sync.Mutex{},
	}
}
