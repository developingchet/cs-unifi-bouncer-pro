package logger

import (
	"io"

	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
)

// ForwardLogrus routes the global logrus logger, which the CrowdSec client
// libraries write to, through log. Their lines then share the configured
// format, level, and secret redaction instead of bypassing all three.
func ForwardLogrus(log zerolog.Logger) {
	std := logrus.StandardLogger()
	std.SetOutput(io.Discard)
	std.SetLevel(toLogrusLevel(log.GetLevel()))
	std.ReplaceHooks(logrus.LevelHooks{})
	std.AddHook(&zerologHook{log: log.With().Str("component", "crowdsec-client").Logger()})
}

type zerologHook struct {
	log zerolog.Logger
}

func (h *zerologHook) Levels() []logrus.Level { return logrus.AllLevels }

func (h *zerologHook) Fire(e *logrus.Entry) error {
	// WithLevel never exits or panics; logrus handles Fatal and Panic itself.
	ev := h.log.WithLevel(toZerologLevel(e.Level))
	for k, v := range e.Data {
		ev = ev.Interface(k, v)
	}
	ev.Msg(e.Message)
	return nil
}

// The client libraries log full HTTP exchanges at debug, so their debug and
// trace output appears only at LOG_LEVEL=trace.
func toZerologLevel(l logrus.Level) zerolog.Level {
	switch l {
	case logrus.TraceLevel, logrus.DebugLevel:
		return zerolog.TraceLevel
	case logrus.InfoLevel:
		return zerolog.InfoLevel
	case logrus.WarnLevel:
		return zerolog.WarnLevel
	case logrus.ErrorLevel:
		return zerolog.ErrorLevel
	case logrus.FatalLevel:
		return zerolog.FatalLevel
	default:
		return zerolog.PanicLevel
	}
}

func toLogrusLevel(l zerolog.Level) logrus.Level {
	switch l {
	case zerolog.TraceLevel:
		return logrus.TraceLevel
	case zerolog.DebugLevel, zerolog.InfoLevel:
		return logrus.InfoLevel
	case zerolog.WarnLevel:
		return logrus.WarnLevel
	default:
		return logrus.ErrorLevel
	}
}
