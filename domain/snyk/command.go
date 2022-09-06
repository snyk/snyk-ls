package snyk

const (
	NavigateToRangeCommand = "snyk.navigateToRange"
	WorkspaceScanCommand   = "snyk.workspace.scan"
	OpenBrowserCommand     = "snyk.openBrowser"
	LoginCommand           = "snyk.login"
	CopyAuthLinkCommand    = "snyk.copyAuthLink"
	LogoutCommand          = "snyk.logout"
)

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

type CommandName string
