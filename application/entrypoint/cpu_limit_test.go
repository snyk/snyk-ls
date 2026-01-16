package entrypoint

import "testing"

func Test_desiredMaxProcs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		numCPU int
		want   int
	}{
		{name: "numCPU=1", numCPU: 1, want: 1},
		{name: "numCPU=2", numCPU: 2, want: 1},
		{name: "numCPU=3", numCPU: 3, want: 1},
		{name: "numCPU=4", numCPU: 4, want: 2},
		{name: "numCPU=7", numCPU: 7, want: 3},
		{name: "numCPU=8", numCPU: 8, want: 4},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := desiredMaxProcs(tc.numCPU); got != tc.want {
				t.Fatalf("desiredMaxProcs(%d) = %d, want %d", tc.numCPU, got, tc.want)
			}
		})
	}
}
