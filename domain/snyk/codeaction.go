package snyk

type CodeAction struct {
	/**
	 * A short, human-readable, title for this code action.
	 */
	Title string

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
	 * The workspace edit this code action performs.
	 */
	Edit WorkspaceEdit

	Command Command
}
