package util

import (
	"github.com/rs/zerolog/log"
	ignore "github.com/sabhiram/go-gitignore"
)

func Ignored(gitIgnore *ignore.GitIgnore, path string) bool {
	ignored := false
	ignored = gitIgnore.MatchesPath(path)
	if ignored {
		log.Trace().Str("method", "ignored").Str("path", path).Msg("matched")
		return true
	}
	log.Trace().Str("method", "ignored").Str("path", path).Msg("not matched")
	return false
}
