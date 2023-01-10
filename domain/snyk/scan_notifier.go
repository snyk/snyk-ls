package snyk

type ScanNotifier interface {
	SendInProgress(folderPath string)
	SendSuccess(folderPath string) //TODO - add parameter with results
	SendError(folderPath string)
}
