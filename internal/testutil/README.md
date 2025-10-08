# Test Utilities

This package provides test setup utilities for the snyk-ls project.

## Unit Test Setup

### Using `testutil.UnitTest(t)`

For unit tests, always use `testutil.UnitTest(t)` to create a test configuration:

```go
func TestMyFeature(t *testing.T) {
    c := testutil.UnitTest(t)
    // ... your test code
}
```

**Important**: `UnitTest(t)` creates a configuration with a **mock workflow engine** that prevents real network calls. Any attempt to make real HTTP requests will cause the test to fail immediately.

### Dependency Injection for Tests

After setting up the config, you need to initialize the dependency injection container. **Always use `di.TestInit(t)` for unit tests**:

```go
func TestMyFeature(t *testing.T) {
    c := testutil.UnitTest(t)
    di.TestInit(t)  // Use TestInit, NOT di.Init()
    // ... your test code
}
```

**Never use `di.Init()` in unit tests** - it creates real API clients and scanners that can make network calls.

### When to Use What

| Test Type | Config Setup | DI Setup | Network Calls |
|-----------|--------------|----------|---------------|
| Unit Test | `testutil.UnitTest(t)` | `di.TestInit(t)` | ❌ Blocked |
| Integration Test | `testutil.IntegTest(t)` | `di.Init()` | ✅ Allowed |
| Smoke Test | `testutil.SmokeTest(t, false)` | `di.Init()` | ✅ Allowed |

## Mock Network Access

The `UnitTest(t)` function automatically sets up a mock network layer that:

1. **Prevents real HTTP calls**: Any attempt to make a real HTTP request will fail the test immediately
2. **Uses fake authentication**: Sets `FakeAuthentication` mode
3. **Uses mock HTTP clients**: All HTTP clients return errors on real requests

This ensures unit tests:
- Run fast (no network latency)
- Are reliable (no external dependencies)
- Are secure (no real tokens or credentials used)
- Can run offline

## Setting Up Engine Mocks

If you need to customize the mock engine, use `SetupEngineMockWithNetworkAccess(t)`:

```go
func TestWithCustomEngine(t *testing.T) {
    c := testutil.UnitTest(t)
    mockEngine, engineConfig := testutil.SetupEngineMockWithNetworkAccess(t)
    
    // Customize mock expectations
    mockEngine.EXPECT().SomeMethod().Return(someValue).Times(1)
    
    // ... your test code
}
```

## Common Patterns

### Testing with Workspace

```go
func TestWorkspaceFeature(t *testing.T) {
    c := testutil.UnitTest(t)
    di.TestInit(t)
    
    // Workspace is already set up by di.TestInit
    workspace := c.Workspace()
    // ... test workspace functionality
}
```

### Testing with Mock Scanner

```go
func TestScanFeature(t *testing.T) {
    c := testutil.UnitTest(t)
    di.TestInit(t)
    
    // di.TestInit provides mock scanners
    scanner := di.Scanner()
    // ... test scanning functionality
}
```

## Troubleshooting

### "attempted real HTTP call in unit test"

If you see this error, it means:
1. You're using `di.Init()` instead of `di.TestInit(t)` in a unit test
2. You're creating HTTP clients directly instead of using mocks
3. You're calling code that bypasses the mock network layer

**Solution**: Use `di.TestInit(t)` and ensure all network access goes through the config's engine.

### Tests are slow

If unit tests are taking a long time:
1. Check if you're using `testutil.IntegTest(t)` or `testutil.SmokeTest(t)` - these allow real network calls
2. Ensure you're using `di.TestInit(t)` not `di.Init()`
3. Check for any direct HTTP client creation

### "engine not initialized"

If you see engine-related errors:
1. Make sure you call `testutil.UnitTest(t)` before accessing the engine
2. Ensure `di.TestInit(t)` is called if you need DI components

## Best Practices

1. ✅ **DO** use `testutil.UnitTest(t)` for all unit tests
2. ✅ **DO** use `di.TestInit(t)` when you need DI components
3. ✅ **DO** use table-driven tests for multiple scenarios
4. ❌ **DON'T** use `di.Init()` in unit tests
5. ❌ **DON'T** create real HTTP clients in unit tests
6. ❌ **DON'T** use real tokens or credentials in unit tests
7. ❌ **DON'T** skip tests because they make network calls - fix them instead

## Migration Guide

If you have existing tests that make network calls:

### Before
```go
func TestMyFeature(t *testing.T) {
    t.Skip("Skipping since it makes real network calls")
    c := testutil.UnitTest(t)
    di.Init()  // ❌ Wrong - makes real network calls
    // ... test code
}
```

### After
```go
func TestMyFeature(t *testing.T) {
    c := testutil.UnitTest(t)
    di.TestInit(t)  // ✅ Correct - uses mocks
    // ... test code
}
```

## See Also

- `mock_network.go` - Mock network access implementation
- `test_setup.go` - Test configuration setup functions
- `application/di/test_init.go` - Test dependency injection setup
