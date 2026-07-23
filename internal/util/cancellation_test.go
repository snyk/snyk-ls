/*
 * © 2026 Snyk Limited
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

package util

import (
	"context"
	"errors"
	"fmt"
	"testing"

	pkgerrors "github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestIsCancellation(t *testing.T) {
	t.Run("true for context.Canceled", func(t *testing.T) {
		assert.True(t, IsCancellation(context.Canceled))
	})

	t.Run("false for context.DeadlineExceeded", func(t *testing.T) {
		// A deadline firing is a genuine timeout, not a user-driven cancel: it must surface.
		assert.False(t, IsCancellation(context.DeadlineExceeded))
	})

	t.Run("true for a wrapped context.Canceled", func(t *testing.T) {
		wrapped := fmt.Errorf("error getting creds with snyk config get api: %w", context.Canceled)
		assert.True(t, IsCancellation(wrapped))
	})

	t.Run("true for a context.Canceled wrapped by pkg/errors", func(t *testing.T) {
		// getToken wraps CLI errors with github.com/pkg/errors.Wrap; confirm that unwrap path too.
		wrapped := pkgerrors.Wrap(context.Canceled, "error getting creds with snyk config get api")
		assert.True(t, IsCancellation(wrapped))
	})

	t.Run("false for nil", func(t *testing.T) {
		assert.False(t, IsCancellation(nil))
	})

	t.Run("false for an unrelated error", func(t *testing.T) {
		assert.False(t, IsCancellation(errors.New("signal: killed")))
	})
}

func TestIsTimeout(t *testing.T) {
	t.Run("true for context.DeadlineExceeded", func(t *testing.T) {
		assert.True(t, IsTimeout(context.DeadlineExceeded))
	})

	t.Run("true for a wrapped context.DeadlineExceeded", func(t *testing.T) {
		assert.True(t, IsTimeout(fmt.Errorf("oauth authentication timed out: %w", context.DeadlineExceeded)))
	})

	t.Run("false for context.Canceled", func(t *testing.T) {
		assert.False(t, IsTimeout(context.Canceled))
	})

	t.Run("false for nil", func(t *testing.T) {
		assert.False(t, IsTimeout(nil))
	})

	t.Run("false for an unrelated error", func(t *testing.T) {
		assert.False(t, IsTimeout(errors.New("boom")))
	})
}
