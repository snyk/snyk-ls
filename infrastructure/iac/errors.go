package iac

const (
	noLoadableInputErrorCode          = 2114
	invalidJsonFileErrorCodeErrorCode = 1021
	failedToParseInputErrorCode       = 2105
	notRecognizedOptionErrorCode      = 422
)

// Ignoring IAC errors for .json files with broken syntax.
// There are cases where there are no IAC files to scan, but
// IAC finds a random malformed JSON file and return an error.
var ignorableIacErrorCodes = map[int]bool{
	noLoadableInputErrorCode:          true,
	invalidJsonFileErrorCodeErrorCode: true,
	failedToParseInputErrorCode:       true,
	notRecognizedOptionErrorCode:      true,
}
