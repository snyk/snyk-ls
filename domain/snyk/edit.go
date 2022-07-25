package snyk

type TextEdit struct {
	/**
	 * The range of the text document to be manipulated. To insert
	 * text into a document create a range where start === end.
	 */
	Range Range

	/**
	 * The string to be inserted. For delete operations use an
	 * empty string.
	 */
	NewText string
}

type WorkspaceEdit struct {
	/**
	 * Holds changes to existing resources.
	 */
	Changes map[string][]TextEdit
}
