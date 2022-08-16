package float

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToFixed(t *testing.T) {
	testTable := []struct {
		input     float64
		precision int
		output    float64
	}{
		{1.23456789, 2, 1.23},                         // normal case, 2 decimal places
		{1.23446789, 3, 1.234},                        // normal case, 3 decimal places
		{1.245, 2, 1.25},                              // rounding case, 2 decimal places
		{1.23456789, 3, 1.235},                        // rounding case, 3 decimal places
		{9999999999999999.15, 2, 9999999999999999.15}, // large input fraction
		{3.40282346638528859811704183484516925440000000000000, 2, 3.40}, // large input precision
	}

	for _, s := range testTable {
		assert.Equal(t, s.output, ToFixed(s.input, s.precision))
	}
}
