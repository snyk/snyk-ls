package config

import (
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

func (c *Config) determineJavaHome(method string) {
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome != "" {
		c.updatePath(javaHome + string(os.PathSeparator) + "bin")
	} else {
		java := c.findJava()
		absJavaPath, err := filepath.Abs(java)
		if err != nil {
			log.Warn().Str("method", method).
				Err(err).
				Str("path", java).
				Msg("couldn't get absolute filepath for found java exec")
		}
		c.updatePath(absJavaPath)
		if absJavaPath != "" {
			err = os.Setenv("JAVA_HOME", filepath.Dir(filepath.Dir(java)))
			if err != nil {
				log.Warn().Str("method", method).Msg("couldn't add java home to environment")
			}
		}
	}
}
