package error_reporting

type ErrorReporter interface {
	FlushErrorReporting()
	CaptureError(err error) bool
}
