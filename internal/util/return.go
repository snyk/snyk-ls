package util

// Result returns the result of a function call and ignores the error.
// This saves lines when you don't care about the error and want to inline the call.
//
// For example, instead of writing:
// val, _ := someFunc()
// foo(val)
//
// You can write:
// foo(Result(someFunc()))
func Result[t any](value t, _ error) t { return value }
