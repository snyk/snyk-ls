package command

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestConfigurationCommand_Execute(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockServer := mock_types.NewMockServer(ctrl)

	cmdData := types.CommandData{
		CommandId: types.WorkspaceConfigurationCommand,
	}

	cmd := &configurationCommand{
		command: cmdData,
		srv:     mockServer,
		logger:  c.Logger(),
		c:       c,
	}

	result, err := cmd.Execute(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Verify the response contains uri and content
	resultMap, ok := result.(map[string]interface{})
	assert.True(t, ok, "Result should be a map")
	assert.Contains(t, resultMap, "uri", "Result should contain uri")
	assert.Contains(t, resultMap, "content", "Result should contain content")
	assert.Equal(t, "snyk://settings", resultMap["uri"])
	
	content, ok := resultMap["content"].(string)
	assert.True(t, ok, "Content should be a string")
	assert.NotEmpty(t, content, "HTML content should not be empty")
}
