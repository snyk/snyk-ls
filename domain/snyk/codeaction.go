/*
 * © 2022-2025 Snyk Limited
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

package snyk

import (
	"errors"

	"github.com/google/uuid"

	"github.com/snyk/snyk-ls/internal/types"
)

var (
	_ types.CodeAction = (*CodeAction)(nil)
	_ types.Groupable  = (*CodeAction)(nil)
)

// CodeAction represents a code action that can be executed by the client using an in-document menu.
// This type should be created by the NewCodeAction or NewDeferredCodeAction functions.
//
// There are 3 types of code actions:
// - No Edit + No CommandData - Deferred code action, which means that either DeferredEdit or DeferredCommand must be set.
// - Only edit/Only command - Resolved immediately to run the edit/command.
// - Both edit and command - Resolved immediately to run edit first and then command.
type CodeAction struct {
	// Title is a short, human-readable, title for this code action.
	Title string

	IsPreferred *bool

	// Edit is an optional WorkspaceEdit literal that can be executed by the client.
	Edit *types.WorkspaceEdit

	// DeferredEdit is a function that returns a WorkspaceEdit.
	// Used for heavy calculations that shouldn't be done ahead of time.
	// A CodeAction cannot have both Edit and DeferredEdit.
	DeferredEdit *func() *types.WorkspaceEdit `json:"-"`

	// Command that will be executed after the Edit (if present).
	Command *types.CommandData

	// DeferredCommand is a function that returns a Command.
	// Used for heavy calculations that shouldn't be done ahead of time.
	// A CodeAction cannot have both Command and DeferredCommand.
	DeferredCommand *func() *types.CommandData `json:"-"`

	// UUID is a unique identifier for this code action. This is used for deferred resolution of a command or edit.
	Uuid *uuid.UUID

	// GroupingKey allows to identify the grouping criterium in a code action
	GroupingKey types.Key

	// The value of the grouping key
	GroupingValue any

	// The type of grouping to determine the grouping function to be used
	GroupingType types.GroupingType
}

func (c *CodeAction) SetEdit(edit *types.WorkspaceEdit) {
	c.Edit = edit
}

func (c *CodeAction) SetTitle(title string) {
	c.Title = title
}

func (c *CodeAction) GetTitle() string {
	return c.Title
}

func (c *CodeAction) GetIsPreferred() *bool {
	return c.IsPreferred
}

func (c *CodeAction) GetEdit() *types.WorkspaceEdit {
	return c.Edit
}

func (c *CodeAction) GetDeferredEdit() *func() *types.WorkspaceEdit {
	return c.DeferredEdit
}

func (c *CodeAction) GetCommand() *types.CommandData {
	return c.Command
}

func (c *CodeAction) GetDeferredCommand() *func() *types.CommandData {
	return c.DeferredCommand
}

func (c *CodeAction) GetUuid() *uuid.UUID {
	return c.Uuid
}

func (c *CodeAction) GetGroupingKey() types.Key {
	return c.GroupingKey
}

func (c *CodeAction) GetGroupingValue() any {
	return c.GroupingValue
}

func (c *CodeAction) GetGroupingType() types.GroupingType {
	return c.GroupingType
}

func NewCodeAction(title string, edit *types.WorkspaceEdit, command *types.CommandData) (*CodeAction, error) {
	if edit == nil && command == nil {
		return nil, errors.New("a non-deferred action must have either an edit or a command")
	}

	action := CodeAction{
		Title:   title,
		Edit:    edit,
		Command: command,
	}
	return &action, nil
}

func NewDeferredCodeAction(
	title string,
	deferredEdit *func() *types.WorkspaceEdit,
	deferredCommand *func() *types.CommandData,
	groupingKey types.Key,
	groupingValue any,
) (CodeAction, error) {
	if deferredEdit == nil && deferredCommand == nil {
		return CodeAction{}, errors.New("deferredEdit and deferredCommand cannot both be nil")
	}
	id := uuid.New()
	// if no grouping key is given, we use the uuid, that way it's never grouped
	if groupingKey == "" || groupingValue == nil {
		groupingKey = types.Key(id.String())
	}
	action := CodeAction{
		Title:           title,
		DeferredEdit:    deferredEdit,
		DeferredCommand: deferredCommand,
		Uuid:            &id,
		GroupingKey:     groupingKey,
		GroupingValue:   groupingValue,
		GroupingType:    types.Quickfix,
	}
	return action, nil
}
