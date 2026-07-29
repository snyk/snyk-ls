package server

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

func Test_folderConfigNotificationMatchesValidators(t *testing.T) {
	t.Parallel()

	repo := types.FilePath("/repo")
	other := types.FilePath("/other")
	noop := func(types.LspFolderConfig) {}

	t.Run("exact match", func(t *testing.T) {
		t.Parallel()
		param := types.LspConfigurationParam{
			FolderConfigs: []types.LspFolderConfig{
				{FolderPath: repo},
				{FolderPath: other},
			},
		}
		validators := map[types.FilePath]func(types.LspFolderConfig){
			repo:  noop,
			other: noop,
		}
		assert.True(t, folderConfigNotificationMatchesValidators(param, validators))
	})

	t.Run("rejects stale extra folder", func(t *testing.T) {
		t.Parallel()
		param := types.LspConfigurationParam{
			FolderConfigs: []types.LspFolderConfig{
				{FolderPath: repo},
				{FolderPath: other},
			},
		}
		validators := map[types.FilePath]func(types.LspFolderConfig){
			repo: noop,
		}
		assert.False(t, folderConfigNotificationMatchesValidators(param, validators))
	})

	t.Run("rejects missing expected folder", func(t *testing.T) {
		t.Parallel()
		param := types.LspConfigurationParam{
			FolderConfigs: []types.LspFolderConfig{
				{FolderPath: repo},
			},
		}
		validators := map[types.FilePath]func(types.LspFolderConfig){
			repo:  noop,
			other: noop,
		}
		assert.False(t, folderConfigNotificationMatchesValidators(param, validators))
	})
}
