package ux

type Analytics interface {
	Initialise()
	Shutdown() error
	Identify()
	AnalysisIsReady(properties AnalysisIsReadyProperties)
	AnalysisIsTriggered(properties AnalysisIsTriggeredProperties)
	IssueHoverIsDisplayed(properties IssueHoverIsDisplayedProperties)
	PluginIsUninstalled(properties PluginIsUninstalledProperties)
	PluginIsInstalled(properties PluginIsInstalledProperties)
}
