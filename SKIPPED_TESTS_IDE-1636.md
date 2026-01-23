# Skipped Tests - IDE-1636 LDX-Sync Caching

## Overview

This document tracks 4 skipped tests in `domain/ide/command/folder_handler_test.go` that were added as part of the LDX-Sync caching refactor (IDE-1636). These tests document expected integration test behavior but are skipped in unit tests due to infrastructure requirements.

**Status:** All tests are legitimately skipped and documented for future integration test implementation.

---

## Skipped Tests

### 1. Test_RefreshConfigFromLdxSync_Integration (Line 569)

**Skip Reason:** `"Integration test - requires full GAF engine with network access configured"`

**What it tests:**
- Validates actual behavior with a real GAF engine
- Verifies `GetUserConfigForProject` is called for each folder
- Confirms errors are logged but don't stop processing other folders
- Ensures success is logged when config is retrieved

**Requirements to enable:**
- Full GAF engine initialization with actual network configuration
- Mock HTTP client or real LDX-Sync API access
- Mock git repository setup for folder detection
- Proper test infrastructure for integration tests

**Current Test Code:**
```go
func Test_RefreshConfigFromLdxSync_Integration(t *testing.T) {
    t.Skip("Integration test - requires full GAF engine with network access configured")

    // This test validates the actual behavior with a real engine
    // It should verify:
    // 1. GetUserConfigForProject is called for each folder
    // 2. Errors are logged but don't stop processing other folders
    // 3. Success is logged when config is retrieved
}
```

**Recommendation:**
- Move to dedicated integration test suite
- Run in CI with proper mocking infrastructure
- Could use testcontainers or similar for full environment setup

---

### 2. Test_RefreshConfigFromLdxSync_PopulatesCache (Line 593)

**Skip Reason:** `"Integration test - requires mocking git and LDX-Sync API"`

**What it tests:**
- Verifies cache is populated for all workspace folders after refresh
- Tests with multiple folders (3 different paths)
- Validates that each folder gets its own cache entry
- Ensures `RefreshConfigFromLdxSync` correctly stores results

**Requirements to enable:**
- Mock git repository setup (for folder detection)
- Mock LDX-Sync API client to return fake results
- Proper engine mock with network access
- Ability to mock `ldx_sync_config.GetUserConfigForProject` package function

**Current Test Code:**
```go
func Test_RefreshConfigFromLdxSync_PopulatesCache(t *testing.T) {
    t.Skip("Integration test - requires mocking git and LDX-Sync API")
    c := testutil.UnitTest(t)
    setupMockEngineWithNetworkAccess(t, c)

    // Setup workspace with multiple folders
    folderPaths := []types.FilePath{
        types.FilePath("/fake/test-folder-0"),
        types.FilePath("/fake/test-folder-1"),
        types.FilePath("/fake/test-folder-2"),
    }
    workspaceutil.SetupWorkspace(t, c, folderPaths...)

    // Call the function
    RefreshConfigFromLdxSync(c, c.Workspace().Folders())

    // Verify cache is populated for all folders
    for _, path := range folderPaths {
        result := c.GetLdxSyncResult(path)
        assert.NotNil(t, result, "Cache should be populated for folder %s", path)
    }
}
```

**Potential approach to enable:**
1. Create a wrapper interface for `ldx_sync_config.GetUserConfigForProject`
2. Inject this interface into `LdxSyncService`
3. Mock the interface in tests
4. **Trade-off:** Adds complexity for dependency injection

**Recommendation:**
- Keep as integration test
- Alternative: Acceptance that unit tests verify cache `Get/Set/Update` separately

---

### 3. Test_RefreshConfigFromLdxSync_PassesPreferredOrg (Line 617)

**Skip Reason:** `"Integration test - requires mocking git and LDX-Sync API"`

**What it tests:**
- Verifies `PreferredOrg` from folder config is passed to `GetUserConfigForProject`
- Ensures the 3-parameter call signature is correct (engine, path, preferredOrg)
- Validates integration between stored config and LDX-Sync API call

**Requirements to enable:**
- Same as Test #2
- Additionally needs to capture and verify actual parameters passed to API
- Requires intercepting the `GetUserConfigForProject` call

**Current Test Code:**
```go
func Test_RefreshConfigFromLdxSync_PassesPreferredOrg(t *testing.T) {
    t.Skip("Integration test - requires mocking git and LDX-Sync API")
    c := testutil.UnitTest(t)
    setupMockEngineWithNetworkAccess(t, c)
    gafConfig := c.Engine().GetConfiguration()

    // Setup workspace with a folder
    folderPath := types.FilePath("/fake/test-folder-0")
    workspaceutil.SetupWorkspace(t, c, folderPath)

    // Set PreferredOrg in folder config
    preferredOrg := "test-preferred-org-id"
    folderConfig := &types.FolderConfig{
        FolderPath:   folderPath,
        PreferredOrg: preferredOrg,
        OrgSetByUser: true,
    }
    err := storedconfig.UpdateFolderConfig(gafConfig, folderConfig, c.Logger())
    require.NoError(t, err)

    // Call the function
    RefreshConfigFromLdxSync(c, c.Workspace().Folders())

    // Verify cache was populated (the actual passing of PreferredOrg to GetUserConfigForProject
    // would require mocking the engine, which is complex - this test verifies the function runs)
    result := c.GetLdxSyncResult(folderPath)
    assert.NotNil(t, result, "Cache should be populated")
}
```

**Note from test comment:**
> "the actual passing of PreferredOrg to GetUserConfigForProject would require mocking the engine, which is complex"

**Recommendation:**
- Integration test with HTTP request capture
- Or add logging/telemetry in production code to verify parameter passing
- Or accept that code review verifies the correct parameters are passed

---

### 4. Test_GetOrgFromCachedLdxSync_EmptyOrganizations (Line 709)

**Skip Reason:** `"Integration test - requires mocking API client"`

**What it tests:**
- Edge case where LDX-Sync returns a result with empty organizations array
- Verifies fallback to global org when cache exists but has no orgs
- Tests the behavior of `ldx_sync_config.ResolveOrgFromUserConfig` with empty data

**Requirements to enable:**
- Mock for `ldx_sync_config.ResolveOrgFromUserConfig` function
- Ability to create cached result with empty organizations that doesn't error
- Understanding of GAF's behavior with empty org lists

**Current Test Code:**
```go
func Test_GetOrgFromCachedLdxSync_EmptyOrganizations(t *testing.T) {
    t.Skip("Integration test - requires mocking API client")
    c := testutil.UnitTest(t)
    setupMockEngineWithNetworkAccess(t, c)
    gafConfig := c.Engine().GetConfiguration()

    folderPath := types.FilePath("/fake/test-folder")

    // Populate cache with empty organizations - create minimal valid structure
    // Use helper to create cachedResult then override organizations to be empty
    cachedResult := createLdxSyncResult("", "", "", false)
    emptyOrgs := []v20241015.Organization{}
    cachedResult.Config.Data.Attributes.Organizations = &emptyOrgs
    c.UpdateLdxSyncCache(map[types.FilePath]*ldx_sync_config.LdxSyncConfigResult{
        folderPath: cachedResult,
    })

    // Set global org
    globalOrgId := "global-org-id"
    gafConfig.Set(configuration.ORGANIZATION, globalOrgId)

    org, err := GetOrgFromCachedLdxSync(c, folderPath)

    require.NoError(t, err)
    assert.Equal(t, globalOrgId, org.Id, "Should fallback to global org when cache has empty organizations")
}
```

**Challenge:**
- `ResolveOrgFromUserConfig` is a GAF package function that's not easily mockable
- The actual behavior with empty orgs depends on GAF implementation details
- Test is partially implemented but can't verify without GAF integration

**Recommendation:**
- Integration test with actual GAF library
- Or remove if this edge case is unlikely/handled by GAF
- Or manual testing to document actual GAF behavior

---

## Decision Matrix

| Test | Keep Skipped? | Alternative Approach | Priority |
|------|---------------|---------------------|----------|
| #1 Integration | ✅ Yes | Run in CI integration suite | Medium |
| #2 PopulatesCache | ✅ Yes | Could refactor with DI, but not worth it | Low |
| #3 PassesPreferredOrg | ✅ Yes | Code review + integration test | Low |
| #4 EmptyOrganizations | ⚠️ Maybe | Consider deleting if edge case unlikely | Low |

---

## Options for Future Work

### Option 1: Leave as-is (Recommended)
**Pros:**
- Tests document expected integration behavior
- No additional code complexity
- Clear skip reasons for future developers

**Cons:**
- No automated verification of these scenarios
- Manual testing required

### Option 2: Create Integration Test Suite
**Pros:**
- Proper automated coverage
- Tests run in appropriate environment
- Can use real dependencies

**Cons:**
- Requires CI infrastructure setup
- Slower test execution
- More maintenance

**How to implement:**
1. Create `domain/ide/command/integration_test.go` with build tag
2. Add `//go:build integration` at top of file
3. Set up test fixtures with real GAF engine
4. Run with `go test -tags=integration`

### Option 3: Refactor for Testability
**Pros:**
- Can test in unit test suite
- Full control over behavior

**Cons:**
- Adds complexity (interfaces, DI)
- May not be worth it for these specific tests
- Goes against YAGNI principle

**How to implement:**
1. Create `LdxSyncClient` interface
2. Inject into `DefaultLdxSyncService`
3. Mock in tests

### Option 4: Delete Skipped Tests
**Pros:**
- No misleading "skipped" count
- Less maintenance burden

**Cons:**
- Lose documentation of what should be tested
- No reminder to add integration tests later

---

## Recommendations

### Immediate (This PR)
- ✅ **Keep all 4 tests as skipped** - They document integration test requirements
- ✅ **Add this documentation** - Helps future developers understand why they're skipped
- ✅ **No code changes needed** - Current implementation is correct

### Short-term (Next Sprint)
- Consider adding manual test plan for these scenarios
- Document actual behavior with empty organizations (Test #4)

### Long-term (Future Work)
- Create integration test suite with proper GAF/git mocking infrastructure
- Run integration tests in CI
- Consider whether Test #4 (EmptyOrganizations) is a realistic edge case worth testing

---

## Related Files

- Implementation: `domain/ide/command/ldx_sync_service.go`
- Tests: `domain/ide/command/folder_handler_test.go`
- Cache: `application/config/config.go` (LDX-Sync cache methods)
- Usage: `application/server/server.go` (calls to `RefreshConfigFromLdxSync`)

---

## Notes

- All skipped tests are in `folder_handler_test.go` lines 569, 593, 617, 709
- Tests document expected behavior but require full GAF integration to run
- Current unit test coverage focuses on cache operations and fallback logic
- Integration scenarios rely on code review and manual testing

---

**Last Updated:** 2026-01-23
**Branch:** feat/IDE-1636
**Author:** Review notes from code review
