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

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/types"
)

type Installer interface {
	Find() (string, error)
	Install(ctx context.Context) (string, error)
	Update(ctx context.Context) (bool, error)
}

type Install struct {
	errorReporter   error_reporting.ErrorReporter
	httpClient      func() *http.Client
	engine          workflow.Engine
	configResolver  types.ConfigResolverInterface
	progressTracker *progress.Tracker
	// lockFileTTL and lockPollInterval bound how long installRelease/updateFromRelease
	// wait for a sibling process's fresh lock file to clear (see createLockFile).
	// Overridable per-instance by tests; production callers get the defaults below.
	lockFileTTL      time.Duration
	lockPollInterval time.Duration
}

func NewInstaller(engine workflow.Engine, errorReporter error_reporting.ErrorReporter, client func() *http.Client, configResolver types.ConfigResolverInterface, progressTracker *progress.Tracker) *Install {
	return &Install{
		errorReporter:    errorReporter,
		httpClient:       client,
		engine:           engine,
		configResolver:   configResolver,
		progressTracker:  progressTracker,
		lockFileTTL:      defaultLockFileTTL,
		lockPollInterval: defaultLockPollInterval,
	}
}

func (i *Install) newDownloader() *Downloader {
	d := NewDownloader(i.engine, i.errorReporter, i.httpClient, i.progressTracker)
	d.lockFileTTL = i.lockFileTTL
	d.lockPollInterval = i.lockPollInterval
	return d
}

func (i *Install) Find() (string, error) {
	d := &Discovery{}
	execPath, _ := d.LookConfigPath(i.configResolver)
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
	r := NewCLIRelease(i.engine, i.httpClient)
	latestRelease, err := r.GetLatestRelease()
	if err != nil {
		return "", err
	}

	return i.installRelease(latestRelease)
}

func (i *Install) installRelease(release *Release) (string, error) {
	d := i.newDownloader()
	lockFileName, err := createLockFile(i.engine, d)
	if err != nil {
		return "", err
	}
	defer func(name string) { cleanupLockFile(i.engine, name) }(lockFileName)

	cliPath := i.configResolver.GetString(types.SettingCliPath, nil)
	if cliPath == "" {
		return "", fmt.Errorf("CLI path is not configured")
	}
	cliPath = filepath.Clean(cliPath)

	installedCliPath, err := d.Download(release, cliPath, false)
	if err != nil {
		return "", err
	}

	return installedCliPath, nil
}

func (i *Install) Update(ctx context.Context) (bool, error) {
	r := NewCLIRelease(i.engine, i.httpClient)
	latestRelease, err := r.GetLatestRelease()
	if err != nil {
		return false, err
	}

	return i.updateFromRelease(latestRelease)
}

func (i *Install) updateFromRelease(r *Release) (bool, error) {
	d := i.newDownloader()
	lockFileName, err := createLockFile(i.engine, d)
	if err != nil {
		return false, err
	}
	defer func(name string) { cleanupLockFile(i.engine, name) }(lockFileName)

	cliDiscovery := Discovery{}
	latestChecksum, err := expectedChecksum(r, &cliDiscovery)
	if err != nil {
		return false, err
	}

	cliPath := i.configResolver.GetString(types.SettingCliPath, nil)
	if cliPath == "" {
		return false, fmt.Errorf("CLI path is not configured")
	}
	cliPath = filepath.Clean(cliPath)
	err = compareChecksum(i.engine.GetLogger(), latestChecksum, cliPath)
	if err == nil {
		// checksum match, no new version available
		return false, nil
	}

	// Carry out the download of the latest release
	latestCliFile, err := d.Download(r, cliPath, true)
	if err != nil {
		// download failed
		return false, err
	}

	err = replaceOutdatedCli(i.engine, cliPath, latestCliFile)
	if err != nil {
		return false, err
	}

	return true, nil
}

func replaceOutdatedCli(engine workflow.Engine, cliPath string, latestCliFile string) error {
	logger := engine.GetLogger()
	logger.Info().Str("method", "replaceOutdatedCli").Msg("replacing outdated CLI with latest")

	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		tildeExecutableName := cliPath + "~"

		// Cleanup an old executable, if left after previous update.
		// There should be no chance that this is still running due to 4-day update cycle. Any CLI run should be guaranteed to terminate within 4 days.
		if _, err := os.Stat(tildeExecutableName); err == nil {
			err = os.Remove(tildeExecutableName)
			if err != nil {
				logger.Warn().Err(err).Str("method", "replaceOutdatedCli").Msg("couldn't remove old CLI on Windows")
			}
		}

		// Windows allows to rename a running executable even with opened file handle. Another executable can take name of the old executable.
		err := os.Rename(cliPath, tildeExecutableName)
		if err != nil {
			logger.Warn().Err(err).Str("method", "replaceOutdatedCli").Msg("couldn't rename current CLI on Windows")
			return err
		}
		err = os.Rename(latestCliFile, cliPath)
		if err != nil {
			logger.Warn().Err(err).Str("method", "replaceOutdatedCli").Msg("couldn't move latest CLI on Windows")
			return err
		}

		// attempt to cleanup the old executable, if scans aren't running at the moment. If errors, the cleanup will happen on the next update
		_ = os.Remove(tildeExecutableName)

		return nil
	}

	// Unix systems keep executable in memory, fine to move.
	err := os.Rename(latestCliFile, cliPath)
	if err != nil {
		logger.Warn().Err(err).Str("method", "replaceOutdatedCli").Msg("couldn't move latest CLI to replace current CLI")
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

// defaultLockFileTTL is how old an existing lock file must be before it is treated as
// stale (e.g. left behind by a crashed process) rather than an active sibling install.
// This threshold is unchanged from the original hard-fail check; only the action taken
// while a lock is fresh (wait instead of failing immediately) has changed.
const defaultLockFileTTL = 10 * time.Minute

// defaultLockPollInterval is how often waitForLockToClear re-checks a fresh lock file.
const defaultLockPollInterval = 500 * time.Millisecond

func createLockFile(engine workflow.Engine, d *Downloader) (lockfileName string, err error) {
	logger := engine.GetLogger()
	lockFileName, err := config.CLIDownloadLockFileName(engine.GetConfiguration())
	if err != nil {
		msg := "installer lockfile directory could not be created "
		logger.Error().Str("method", "Download").Str("lockfile", lockFileName).Msg(msg)
		return "", errors.New(msg)
	}

	waitForLockToClear(logger, lockFileName, d.lockFileTTL, d.lockPollInterval)

	err = d.createLockFile()
	if err != nil {
		return "", err
	}
	return lockFileName, nil
}

// waitForLockToClear blocks while a sibling process appears to hold a fresh (younger
// than ttl) lock file at lockFileName, polling every pollInterval. A concurrent
// installer's in-progress download - detected via this lock file - no longer aborts
// the caller outright (IDE-2446); instead the caller waits for it to either finish
// (lock file removed) or age past ttl, at which point it is treated as stale, exactly
// as an already-stale lock always was.
func waitForLockToClear(logger *zerolog.Logger, lockFileName string, ttl, pollInterval time.Duration) {
	for {
		fileInfo, statErr := os.Stat(lockFileName)
		if statErr != nil {
			return
		}
		age := time.Since(fileInfo.ModTime())
		if age >= ttl {
			return
		}
		wait := pollInterval
		if remaining := ttl - age; remaining < wait {
			wait = remaining
		}
		logger.Debug().Str("method", "Download").Str("lockfile", lockFileName).
			Dur("age", age).Msg("waiting for sibling installer lockfile to clear")
		time.Sleep(wait)
	}
}

func cleanupLockFile(engine workflow.Engine, lockFileName string) {
	logger := engine.GetLogger()
	file, err := os.Open(lockFileName)
	if err == nil {
		_ = file.Close()
	}
	err = os.Remove(lockFileName)
	if err != nil {
		logger.Error().Str("method", "Download").Str("lockfile", lockFileName).Msg("couldn't clean up lockfile")
	}
}

type FakeInstaller struct {
	updates        int
	installs       int
	mutex          sync.Mutex
	engine         workflow.Engine
	configResolver types.ConfigResolverInterface
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
	logger := t.engine.GetLogger()
	t.mutex.Lock()
	defer t.mutex.Unlock()
	cliPath := t.configResolver.GetString(types.SettingCliPath, nil)
	if cliPath != "" {
		cliPath = filepath.Clean(cliPath)
	}
	path := cliPath
	logger.Debug().Msgf("Installing fake 4-byte CLI to %s", path)
	err := os.WriteFile(path, []byte("fake"), 0755)
	if err != nil {
		return "", err
	}

	t.installs++
	return path, nil
}

func (t *FakeInstaller) Update(_ context.Context) (bool, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.updates++
	return true, nil
}

func NewFakeInstaller(engine workflow.Engine, configResolver types.ConfigResolverInterface) *FakeInstaller {
	return &FakeInstaller{
		mutex:          sync.Mutex{},
		engine:         engine,
		configResolver: configResolver,
	}
}
