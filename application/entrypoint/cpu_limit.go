package entrypoint

import (
	"runtime"

	"github.com/rs/zerolog"
)

func desiredMaxProcs(numCPU int) int {
	desired := numCPU / 2
	if desired < 1 {
		return 1
	}
	return desired
}

func ApplyDefaultCPUCap(logger *zerolog.Logger) {
	if logger == nil {
		return
	}

	desired := desiredMaxProcs(runtime.NumCPU())
	previous := runtime.GOMAXPROCS(desired)
	logger.Info().Int("previous", previous).Int("current", desired).Msg("Applied default GOMAXPROCS CPU cap")
}
