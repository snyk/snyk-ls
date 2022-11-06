package sentry

import (
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog"
)

type BreadcrumbLogger struct{}

func (l *BreadcrumbLogger) Run(_ *zerolog.Event, level zerolog.Level, message string) {
	breadcrumb := sentry.Breadcrumb{
		Type:      level.String(),
		Message:   message,
		Level:     toSentryLevel(level),
		Timestamp: time.Now(),
	}
	sentry.AddBreadcrumb(&breadcrumb)
}

func toSentryLevel(l zerolog.Level) sentry.Level {
	switch l {
	case zerolog.FatalLevel:
	case zerolog.PanicLevel:
		return sentry.LevelFatal
	case zerolog.ErrorLevel:
		return sentry.LevelError
	case zerolog.WarnLevel:
		return sentry.LevelWarning
	case zerolog.TraceLevel:
	case zerolog.DebugLevel:
		return sentry.LevelDebug
	case zerolog.InfoLevel:
		return sentry.LevelInfo
	}

	return sentry.LevelInfo
}
