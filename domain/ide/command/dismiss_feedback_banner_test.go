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

package command

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestDismissFeedbackBanner_Execute_PersistsDismissal(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	require.False(t, config.GetFeedbackBannerDismissed(conf))

	cmd := &dismissFeedbackBanner{
		command: types.CommandData{CommandId: types.DismissFeedbackBanner},
		engine:  engine,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result)
	assert.True(t, config.GetFeedbackBannerDismissed(conf))
}

func TestDismissFeedbackBanner_Command_ReturnsCommandData(t *testing.T) {
	testutil.UnitTest(t)
	cmdData := types.CommandData{CommandId: types.DismissFeedbackBanner}
	cmd := &dismissFeedbackBanner{command: cmdData}
	assert.Equal(t, cmdData, cmd.Command())
}

func TestFeedbackBannerInteracted_Execute_RecordsInteraction(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	require.False(t, config.GetFeedbackBannerInteracted(conf))

	cmd := &feedbackBannerInteracted{
		command: types.CommandData{CommandId: types.FeedbackBannerInteracted},
		engine:  engine,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result)
	assert.True(t, config.GetFeedbackBannerInteracted(conf))
}

func TestFeedbackBannerInteracted_Command_ReturnsCommandData(t *testing.T) {
	testutil.UnitTest(t)
	cmdData := types.CommandData{CommandId: types.FeedbackBannerInteracted}
	cmd := &feedbackBannerInteracted{command: cmdData}
	assert.Equal(t, cmdData, cmd.Command())
}
