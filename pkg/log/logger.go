package log

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func NewLogger(output io.Writer, errOutput io.Writer) *Logger {
	if output == nil && errOutput == nil {
		output = os.Stdout
		errOutput = os.Stderr
	} else if output == nil && errOutput != nil {
		output = errOutput
	} else if output != nil && errOutput == nil {
		errOutput = output
	}

	return &Logger{
		output:    output,
		errOutput: errOutput,
		time:      true,
	}
}

func (l *Logger) SetDebug(debug bool) *Logger {
	l.debug = debug
	return l
}

func format(level logLevel, message string) string {
	message = strings.TrimSpace(message)
	return fmt.Sprintf("[%s] [%s]\t%s", time.Now().Format("2006-01-02 15:04:05 UTC-07"), level, message)
}

func formatWithoutTime(level logLevel, message string) string {
	message = strings.TrimSpace(message)
	return fmt.Sprintf("[%s]\t%s", level, message)
}

func (l *Logger) DisableTime() {
	l.time = false
}

func (l *Logger) print(level logLevel, message string) {
	var out io.Writer
	switch level {
	case ErrorLevel:
		out = l.errOutput
	case FatalLevel:
		out = l.errOutput
	default:
		out = l.output
	}
	if l.time {
		fmt.Fprintln(out, format(level, message))
	} else {
		fmt.Fprintln(out, formatWithoutTime(level, message))
	}
}

func (l *Logger) Info(a ...any) {
	l.print(InfoLevel, fmt.Sprint(a...))
}

func (l *Logger) Warn(a ...any) {
	l.print(WarnLevel, fmt.Sprint(a...))
}

func (l *Logger) Error(a ...any) {
	l.print(ErrorLevel, fmt.Sprint(a...))
}

func (l *Logger) Debug(a ...any) {
	if l.debug {
		l.print(DebugLevel, fmt.Sprint(a...))
	}
}

func (l *Logger) Fatal(a ...any) {
	l.print(FatalLevel, fmt.Sprint(a...))
}

func (l *Logger) Infof(format string, a ...any) {
	l.print(InfoLevel, fmt.Sprintf(format, a...))
}

func (l *Logger) Warnf(format string, a ...any) {
	l.print(WarnLevel, fmt.Sprintf(format, a...))
}

func (l *Logger) Errorf(format string, a ...any) {
	l.print(ErrorLevel, fmt.Sprintf(format, a...))
}

func (l *Logger) Debugf(format string, a ...any) {
	if l.debug {
		l.print(DebugLevel, fmt.Sprintf(format, a...))
	}
}

func (l *Logger) Fatalf(format string, a ...any) {
	l.print(FatalLevel, fmt.Sprintf(format, a...))
}

//

func (l *Logger) NewTagLogger(tag string) TagLoggerInterface {
	return &TagLogger{
		tag:    tag,
		logger: l,
	}
}

func (t *TagLogger) GetTag() string {
	return t.tag
}

func (t *TagLogger) Info(a ...any) {
	t.logger.Info(append([]any{"[", t.tag, "] "}, a...)...)
}

func (t *TagLogger) Warn(a ...any) {
	t.logger.Warn(append([]any{"[", t.tag, "] "}, a...)...)
}

func (t *TagLogger) Error(a ...any) {
	t.logger.Error(append([]any{"[", t.tag, "] "}, a...)...)
}

func (t *TagLogger) Debug(a ...any) {
	t.logger.Debug(append([]any{"[", t.tag, "] "}, a...)...)
}

func (t *TagLogger) Fatal(a ...any) {
	t.logger.Fatal(append([]any{"[", t.tag, "] "}, a...)...)
}

func (t *TagLogger) Infof(format string, a ...any) {
	t.logger.Infof("[%s] %s", t.tag, fmt.Sprintf(format, a...))
}

func (t *TagLogger) Warnf(format string, a ...any) {
	t.logger.Warnf("[%s] %s", t.tag, fmt.Sprintf(format, a...))
}

func (t *TagLogger) Errorf(format string, a ...any) {
	t.logger.Errorf("[%s] %s", t.tag, fmt.Sprintf(format, a...))
}

func (t *TagLogger) Debugf(format string, a ...any) {
	t.logger.Debugf("[%s] %s", t.tag, fmt.Sprintf(format, a...))
}

func (t *TagLogger) Fatalf(format string, a ...any) {
	t.logger.Fatalf("[%s] %s", t.tag, fmt.Sprintf(format, a...))
}

func (t *TagLogger) NewTagLogger(tag string) TagLoggerInterface {
	return &TagLogger{
		tag:    tag,
		logger: t,
	}
}
