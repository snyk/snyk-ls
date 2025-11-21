package command

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sourcegraph/go-lsp"
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

	// We expect a window/showDocument callback
	mockServer.EXPECT().
		Callback(gomock.Any(), "window/showDocument", gomock.Any()).
		DoAndReturn(func(_ context.Context, method string, params interface{}) (interface{}, error) {
			showDocParams, ok := params.(types.ShowDocumentParams)
			assert.True(t, ok)
			assert.Equal(t, lsp.DocumentURI("snyk://settings"), showDocParams.Uri)
			return nil, nil
		}).
		Times(1)

	cmd := &configurationCommand{
		command: cmdData,
		srv:     mockServer,
		logger:  c.Logger(),
		c:       c,
	}

	_, err := cmd.Execute(context.Background())
	assert.NoError(t, err)
}
