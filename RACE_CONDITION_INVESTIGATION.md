# Folder Config Race Condition Investigation

## Problem Statement
Multiple snyk-macos-arm64 processes (6+) are racing to update the same config file located at `~/.config/snyk/ls-config-<IDE_NAME>`. This causes folder configs to disappear - Process A writes 1 folder, Process B reads stale cache (0 folders), Process B overwrites with 0 folders.

Evidence from fs_usage logs:
```
18:14:46.231 - snyk-macos-arm64.18501952 writes
18:14:46.233 - snyk-macos-arm64.18501952 writes AGAIN (2ms later!)
18:14:46.274 - snyk-macos-arm64.18501899 writes (DIFFERENT PROCESS!)
```

## Root Cause Analysis

### Framework Architecture
The storage file contains ALL persisted keys in a single JSON file:
- `INTERNAL_LS_CONFIG` (ConfigMainKey) - folder configs
- `CONFIG_KEY_OAUTH_TOKEN` - OAuth tokens
- `AUTHENTICATION_TOKEN` - auth tokens
- `SNYKLS_INTERNAL_DATAHOME` - data home path
- Any other key marked with `conf.PersistInStorage(key)`

**Critical Framework Bug**: When ANY code calls `conf.Set(key, value)` on ANY persisted key:
1. Framework's `extendedViper.Set()` releases the mutex BEFORE calling `storage.Set()`
2. `storage.Set()` does a read-modify-write of the ENTIRE file WITHOUT file locking
3. Multiple processes can race at the file level

Location: `go-application-framework/pkg/configuration/configuration.go:358-372`

### Three Levels of Race Conditions

1. **In-memory goroutine races**: Multiple goroutines in same process updating ConfigMainKey
2. **Framework bug**: Set() releases mutex before storage.Set() (can't fix without framework changes)
3. **File-level races**: Multiple processes reading/writing same file + stale viper cache

## Attempts Made (All Failed)

### Attempt 1: In-Memory Mutex Only
**Changes:**
- Added `var configMutex sync.Mutex` in `internal/storedconfig/xdg.go:50`
- Wrapped `UpdateFolderConfig()` with mutex.Lock/Unlock

**Result:** FAILED
**Why:** Only protects goroutines within same process, doesn't protect against other processes

### Attempt 2: File Locking
**Changes:**
- Added file lock acquisition in `UpdateFolderConfig()` at `xdg.go:270`
- Added file lock acquisition in `GetFolderConfigWithOptions()` at `stored_config.go:67`
- Pattern:
  ```go
  configMutex.Lock()
  defer configMutex.Unlock()

  storage := conf.GetStorage()
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
  defer cancel()

  err := storage.Lock(ctx, 50*time.Millisecond)
  if err != nil {
      return fmt.Errorf("failed to acquire storage file lock after %v: %w", storageLockTimeout, err)
  }
  defer storage.Unlock()
  ```

**Result:** FAILED
**Why:** Writes were still happening, indicating other code paths were writing without locks

### Attempt 3: Storage Refresh (Cache Invalidation)
**Changes:**
- Added `storage.Refresh(conf, ConfigMainKey)` after acquiring lock in:
  - `UpdateFolderConfig()` at `xdg.go:282`
  - `GetFolderConfigWithOptions()` (write path) at `stored_config.go:79`
  - `GetFolderConfigWithOptions()` (read-only path) at `stored_config.go:123`

**Reasoning:** Each process has its own viper instance with cached config. Without refresh, Process B reads stale cache (0 folders) even after Process A wrote 1 folder to disk.

**Result:** FAILED
**Why:** File was still being modified despite having locking + refresh

### Attempt 4: Commented Out All Writes to Identify Source
**Changes Made:**
1. Commented out `conf.Set(ConfigMainKey, ...)` in `internal/storedconfig/xdg.go:178`
2. File was STILL being modified!
3. This proved writes were NOT coming from our Save() function

**Discovery:** Framework's `storage.Set()` is called whenever ANY persisted key is updated via `conf.Set()`

### Attempt 5: Added File Locking to SetToken()
**Changes:**
- Added file lock + refresh to `SetToken()` in `application/config/config.go:670-691`
- Wrapped `conf.Set(auth.CONFIG_KEY_OAUTH_TOKEN, ...)` at line 697
- Wrapped `conf.Set(configuration.AUTHENTICATION_TOKEN, ...)` at line 701

**Result:** FAILED
**Why:** Still other write paths we hadn't found

### Attempt 6: Commented Out ALL Writes to Storage File
**All locations commented out:**

1. **internal/storedconfig/xdg.go:178**
   ```go
   // conf.Set(ConfigMainKey, string(marshaled))
   ```

2. **application/config/config.go:697-698**
   ```go
   // conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)
   // conf.Set(auth.CONFIG_KEY_OAUTH_TOKEN, newTokenString)
   ```

3. **application/config/config.go:702-703**
   ```go
   // conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, false)
   // conf.Set(configuration.AUTHENTICATION_TOKEN, newTokenString)
   ```

4. **domain/snyk/persistence/file_operation.go:89**
   ```go
   // conf.Set(constants.DataHome, dh)
   ```

5. **application/config/config.go:306**
   ```go
   // conf.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_STANDALONE)
   ```

6. **application/server/configuration.go:713**
   ```go
   // conf.Set(configuration.INSECURE_HTTPS, cliSettings.Insecure)
   ```

7. **infrastructure/featureflag/featureflag.go:80**
   ```go
   // conf.Set(configuration.ORGANIZATION, org)
   ```

8. **infrastructure/featureflag/featureflag.go:87**
   ```go
   // conf.Set(configuration.ORGANIZATION, org)
   ```

9. **application/config/config.go:1240-1242** (Also commented out PersistInStorage)
   ```go
   // conf.PersistInStorage(storedconfig.ConfigMainKey)
   // conf.PersistInStorage(auth.CONFIG_KEY_OAUTH_TOKEN)
   // conf.PersistInStorage(configuration.AUTHENTICATION_TOKEN)
   ```

**Result:** File STILL being modified!
**Conclusion:** There are MORE write paths we haven't found, OR the framework is writing on its own somehow

## Code Locations Modified

### Files with Changes to Revert
1. `internal/storedconfig/xdg.go`
   - Lines 44-45: Added storageLockRetryDelay, storageLockTimeout constants
   - Lines 48-50: Added configMutex
   - Lines 56-64: Added getGoroutineID() debug function
   - Lines 166-179: Commented out saveDirectlyToFile() body
   - Lines 181-195: Added debug logging to Save()
   - Lines 208-209: Updated comment on updateFolderConfigLocked()
   - Lines 246-288: Added locking to UpdateFolderConfig()

2. `internal/storedconfig/stored_config.go`
   - Line 20: Added "context" import
   - Line 22: Added "fmt" import
   - Lines 56-117: Added locking to GetFolderConfigWithOptions() write path
   - Lines 119-126: Added refresh to read-only path

3. `application/config/config.go`
   - Lines 670-691: Added file locking to SetToken()
   - Lines 696-698: Commented out OAuth token writes
   - Lines 701-703: Commented out auth token writes
   - Line 306: Commented out EXECUTION_MODE_KEY write
   - Lines 1240-1242: Commented out PersistInStorage calls

4. `domain/snyk/persistence/file_operation.go`
   - Lines 88-89: Commented out DataHome write

5. `application/server/configuration.go`
   - Lines 712-713: Commented out INSECURE_HTTPS write

6. `infrastructure/featureflag/featureflag.go`
   - Lines 79-80: Commented out ORGANIZATION write
   - Lines 86-87: Commented out ORGANIZATION write

### Debug Artifacts Added
- `trace-config-file.sh` - fs_usage monitoring script
- Debug logging in Save() function with PID, goroutine ID, stack traces

## What We Learned

1. **All persisted keys share ONE file**: Any `conf.Set()` on ANY persisted key triggers a read-modify-write of the entire file

2. **Framework has inherent race**: `extendedViper.Set()` releases mutex before calling `storage.Set()`, making atomic updates impossible without external locking

3. **Viper caching problem**: Each process has its own viper instance. Without `storage.Refresh()`, processes read stale cached data

4. **Multiple write paths**: At least 9+ different locations call `conf.Set()` on persisted keys

5. **Hidden writes**: Even after commenting out all known `conf.Set()` calls, file was still being modified - suggesting framework internals or additional code paths we haven't found

## Next Steps / Open Questions

1. **Find remaining write sources**: Use more aggressive tracing (dtrace/fs_usage with stack traces) to find ALL processes/code writing to the file

2. **Framework-level fix**: Consider patching go-application-framework to:
   - Hold mutex during storage.Set()
   - Add file locking to JsonStorage.Set()
   - Add automatic refresh after acquiring lock

3. **Alternative approach**: Move folder configs to a SEPARATE storage file not shared with auth tokens, to reduce contention

4. **Investigate framework auto-persistence**: Check if framework has background goroutines auto-persisting config on timer/events

5. **Process investigation**: Understand why 6+ separate snyk-macos-arm64 processes exist - one per workspace folder? Can we consolidate?

## Debugging Commands Used

```bash
# Monitor file writes in real-time
sudo fs_usage -w -f filesys | grep --line-buffered "ls-config-Visual Studio Code"

# Find all conf.Set calls
grep -rn "conf\.Set(" --include="*.go" | grep -v test | grep -v "//"

# Check persisted keys
grep -r "PersistInStorage" --include="*.go"
```
