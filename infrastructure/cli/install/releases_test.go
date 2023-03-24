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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestGetLatestRelease_downloadURLShouldBeNotEmpty(t *testing.T) {
	testutil.IntegTest(t)

	r := NewCLIRelease(func() *http.Client { return http.DefaultClient })
	ctx := context.Background()

	release, err := r.GetLatestRelease(ctx)

	assert.NoError(t, err)
	assert.NotEmpty(t, release.Assets.Linux.URL)
}
