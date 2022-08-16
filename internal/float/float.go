package float

import "math"

// The following code should work for a lot of simple use cases with relatively small numbers and small precision inputs. However, it may not work for some uses cases because of numbers overflowing out of the range of float64 numbers, as well as IEEE-754 rounding errors.
// Source: https://stackoverflow.com/a/29786394/1713082
func ToFixed(num float64, precision int) float64 {
	output := math.Pow(10, float64(precision))
	return float64(round(num*output)) / output
}

func round(num float64) int {
	return int(num + math.Copysign(0.5, num))
}
