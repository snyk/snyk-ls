package ux

type Analytics interface {
	AnalysisIsReady(properties AnalysisIsReadyProperties)
	AnalysisIsTriggered(properties AnalysisIsTriggeredProperties)
	IssueHoverIsDisplayed(properties IssueHoverIsDisplayedProperties)
	PluginIsUninstalled(properties PluginIsUninstalledProperties)
	PluginIsInstalled(properties PluginIsInstalledProperties)
}
