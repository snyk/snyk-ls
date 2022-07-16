package snyk

type CodeAction struct {
	/**
	 * A short, human-readable, title for this code action.
	 */
	Title string
	/**
	 * The issues that this code action resolves.
	 */
	Issues []Issue

	/**
	 * Marks this as a preferred action. Preferred actions are used by the `auto fix` command and can be targeted
	 * by keybindings.
	 *
	 * A quick fix should be marked preferred if it properly addresses the underlying error.
	 * A refactoring should be marked preferred if it is the most reasonable choice of actions to take.
	 *
	 * @since 3.15.0
	 */
	IsPreferred bool
	/**
	 * Marks that the code action cannot currently be applied.
	 *
	 * Clients should follow the following guidelines regarding disabled code actions:
	 *
	 *   - Disabled code actions are not shown in automatic [lightbulb](https://code.visualstudio.com/docs/editor/editingevolved#_code-action)
	 *     code action menu.
	 *
	 *   - Disabled actions are shown as faded out in the code action menu when the user request a more specific type
	 *     of code action, such as refactorings.
	 *
	 *   - If the user has a [keybinding](https://code.visualstudio.com/docs/editor/refactoring#_keybindings-for-code-actions)
	 *     that auto applies a code action and only a disabled code actions are returned, the client should show the user an
	 *     error message with `reason` in the editor.
	 *
	 * @since 3.16.0
	 */
	Disabled struct {
		/**
		 * Human readable description of why the code action is currently disabled.
		 *
		 * This is displayed in the code actions UI.
		 */
		Reason string
	}
	/**
	 * The workspace edit this code action performs.
	 */
	Edit WorkspaceEdit
}
