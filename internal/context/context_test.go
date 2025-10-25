/*
 * © 2025 Snyk Limited
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

package context

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanSource_String(t *testing.T) {
	t.Run("LLM returns correct string", func(t *testing.T) {
		require.Equal(t, "LLM", LLM.String())
	})

	t.Run("IDE returns correct string", func(t *testing.T) {
		require.Equal(t, "IDE", IDE.String())
	})
}

func TestNewContextWithScanSource(t *testing.T) {
	t.Run("adds LLM scan source to context", func(t *testing.T) {
		ctx := t.Context()
		newCtx := NewContextWithScanSource(ctx, LLM)

		source, ok := ScanSourceFromContext(newCtx)
		require.True(t, ok)
		require.Equal(t, LLM, source)
	})

	t.Run("adds IDE scan source to context", func(t *testing.T) {
		ctx := t.Context()
		newCtx := NewContextWithScanSource(ctx, IDE)

		source, ok := ScanSourceFromContext(newCtx)
		require.True(t, ok)
		require.Equal(t, IDE, source)
	})
}

func TestScanSourceFromContext(t *testing.T) {
	t.Run("returns false when scan source not in context", func(t *testing.T) {
		ctx := t.Context()

		source, ok := ScanSourceFromContext(ctx)
		require.False(t, ok)
		require.Empty(t, source)
	})

	t.Run("returns correct scan source from context", func(t *testing.T) {
		ctx := NewContextWithScanSource(t.Context(), LLM)

		source, ok := ScanSourceFromContext(ctx)
		require.True(t, ok)
		require.Equal(t, LLM, source)
	})
}

func TestDeltaScanType_String(t *testing.T) {
	t.Run("Reference returns correct string", func(t *testing.T) {
		require.Equal(t, "Reference", Reference.String())
	})

	t.Run("WorkingDirectory returns correct string", func(t *testing.T) {
		require.Equal(t, "WorkingDirectory", WorkingDirectory.String())
	})
}

func TestNewContextWithDeltaScanType(t *testing.T) {
	t.Run("adds Reference delta scan type to context", func(t *testing.T) {
		ctx := t.Context()
		newCtx := NewContextWithDeltaScanType(ctx, Reference)

		dType, ok := DeltaScanTypeFromContext(newCtx)
		require.True(t, ok)
		require.Equal(t, Reference, dType)
	})

	t.Run("adds WorkingDirectory delta scan type to context", func(t *testing.T) {
		ctx := t.Context()
		newCtx := NewContextWithDeltaScanType(ctx, WorkingDirectory)

		dType, ok := DeltaScanTypeFromContext(newCtx)
		require.True(t, ok)
		require.Equal(t, WorkingDirectory, dType)
	})
}

func TestDeltaScanTypeFromContext(t *testing.T) {
	t.Run("returns false when delta scan type not in context", func(t *testing.T) {
		ctx := t.Context()

		dType, ok := DeltaScanTypeFromContext(ctx)
		require.False(t, ok)
		require.Empty(t, dType)
	})

	t.Run("returns correct delta scan type from context", func(t *testing.T) {
		ctx := NewContextWithDeltaScanType(t.Context(), Reference)

		dType, ok := DeltaScanTypeFromContext(ctx)
		require.True(t, ok)
		require.Equal(t, Reference, dType)
	})
}

func TestDependenciesKeyType_String(t *testing.T) {
	t.Run("returns string representation", func(t *testing.T) {
		key := dependenciesKeyType("testKey")
		require.Equal(t, "testKey", key.String())
	})
}

func TestNewContextWithDependencies(t *testing.T) {
	t.Run("adds empty dependencies map to context", func(t *testing.T) {
		ctx := t.Context()
		deps := map[string]any{}
		newCtx := NewContextWithDependencies(ctx, deps)

		retrievedDeps, ok := DependenciesFromContext(newCtx)
		require.True(t, ok)
		require.NotNil(t, retrievedDeps)
		require.Empty(t, retrievedDeps)
	})

	t.Run("adds dependencies with single value to context", func(t *testing.T) {
		ctx := t.Context()
		deps := map[string]any{
			"service1": "value1",
		}
		newCtx := NewContextWithDependencies(ctx, deps)

		retrievedDeps, ok := DependenciesFromContext(newCtx)
		require.True(t, ok)
		require.Equal(t, deps, retrievedDeps)
	})

	t.Run("adds dependencies with multiple values to context", func(t *testing.T) {
		ctx := t.Context()
		deps := map[string]any{
			"service1": "value1",
			"service2": 42,
			"service3": struct{ Name string }{Name: "test"},
		}
		newCtx := NewContextWithDependencies(ctx, deps)

		retrievedDeps, ok := DependenciesFromContext(newCtx)
		require.True(t, ok)
		require.Equal(t, deps, retrievedDeps)
		require.Equal(t, "value1", retrievedDeps["service1"])
		require.Equal(t, 42, retrievedDeps["service2"])
	})
}

func TestDependenciesFromContext(t *testing.T) {
	t.Run("returns false when dependencies not in context", func(t *testing.T) {
		ctx := t.Context()

		deps, ok := DependenciesFromContext(ctx)
		require.False(t, ok)
		require.Nil(t, deps)
	})

	t.Run("returns correct dependencies from context", func(t *testing.T) {
		expectedDeps := map[string]any{
			"testService": "testValue",
		}
		ctx := NewContextWithDependencies(t.Context(), expectedDeps)

		deps, ok := DependenciesFromContext(ctx)
		require.True(t, ok)
		require.Equal(t, expectedDeps, deps)
	})
}

func TestContextChaining(t *testing.T) {
	t.Run("can chain multiple context values", func(t *testing.T) {
		ctx := t.Context()

		// Add all context values
		ctx = NewContextWithScanSource(ctx, LLM)
		ctx = NewContextWithDeltaScanType(ctx, Reference)
		ctx = NewContextWithDependencies(ctx, map[string]any{"key": "value"})

		// Verify all values are present
		source, ok := ScanSourceFromContext(ctx)
		require.True(t, ok)
		require.Equal(t, LLM, source)

		dType, ok := DeltaScanTypeFromContext(ctx)
		require.True(t, ok)
		require.Equal(t, Reference, dType)

		deps, ok := DependenciesFromContext(ctx)
		require.True(t, ok)
		require.Equal(t, "value", deps["key"])
	})
}
