package log

import "io"

type logLevel string

const (
	InfoLevel  logLevel = "Info"
	WarnLevel  logLevel = "Warn"
	ErrorLevel logLevel = "Error"
	DebugLevel logLevel = "Debug"
	FatalLevel logLevel = "Fatal"
)

type LoggerInterface interface {
	Info(a ...any)
	Warn(a ...any)
	Error(a ...any)
	Debug(a ...any)
	Fatal(a ...any)
	Infof(format string, a ...any)
	Warnf(format string, a ...any)
	Errorf(format string, a ...any)
	Debugf(format string, a ...any)
	Fatalf(format string, a ...any)
}

type TagLoggerInterface interface {
	LoggerInterface
	GetTag() string
	NewTagLogger(tag string) TagLoggerInterface
}

type Logger struct {
	output    io.Writer
	errOutput io.Writer
	debug     bool
	time      bool
}

type TagLogger struct {
	tag    string
	logger LoggerInterface
}
