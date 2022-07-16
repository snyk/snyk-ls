package snyk

type Command struct {
	/**
	 * Title of the command, like `save`.
	 */
	Title string
	/**
	 * The identifier of the actual command handler.
	 */
	Command string
	/**
	 * Arguments that the command handler should be
	 * invoked with.
	 */
	Arguments []interface{}
}
