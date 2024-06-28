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

package snyk

import (
	"errors"

	"github.com/google/uuid"
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
	Edit *WorkspaceEdit

	// DeferredEdit is a function that returns a WorkspaceEdit.
	// Used for heavy calculations that shouldn't be done ahead of time.
	// A CodeAction cannot have both Edit and DeferredEdit.
	DeferredEdit *func() *WorkspaceEdit `json:"-"`

	// Command that will be executed after the Edit (if present).
	Command *CommandData

	// DeferredCommand is a function that returns a Command.
	// Used for heavy calculations that shouldn't be done ahead of time.
	// A CodeAction cannot have both Command and DeferredCommand.
	DeferredCommand *func() *CommandData `json:"-"`

	// UUID is a unique identifier for this code action. This is used for deferred resolution of a command or edit.
	Uuid *uuid.UUID
}

func NewCodeAction(title string, edit *WorkspaceEdit, command *CommandData) (CodeAction, error) {
	if edit == nil && command == nil {
		return CodeAction{}, errors.New("a non-deferred action must have either an edit or a command")
	}

	action := CodeAction{
		Title:   title,
		Edit:    edit,
		Command: command,
	}
	return action, nil
}

func NewDeferredCodeAction(title string,
	deferredEdit *func() *WorkspaceEdit,
	deferredCommand *func() *CommandData,
) (CodeAction, error) {
	if deferredEdit == nil && deferredCommand == nil {
		return CodeAction{}, errors.New("deferredEdit and deferredCommand cannot both be nil")
	}
	id := uuid.New()

	action := CodeAction{
		Title:           title,
		DeferredEdit:    deferredEdit,
		DeferredCommand: deferredCommand,
		Uuid:            &id,
	}
	return action, nil
}
