package command

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/rs/zerolog/log"
)

func OpenBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Err(err).Str("method", "domain.ide.command.command.OpenBrowser").Msg("couldn't open browser window")
	}
}
