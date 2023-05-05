package log

type GinLogWriter struct {
	logFunc func(a ...any)
}

func NewGinLogWriter(logger LoggerInterface, level logLevel) *GinLogWriter {
	var logFunc func(a ...any)
	switch level {
	case InfoLevel:
		logFunc = logger.Info
	case WarnLevel:
		logFunc = logger.Warn
	case ErrorLevel:
		logFunc = logger.Error
	case DebugLevel:
		logFunc = logger.Debug
	case FatalLevel:
		logFunc = logger.Fatal
	default:
		logFunc = logger.Info
	}

	return &GinLogWriter{
		logFunc: logFunc,
	}
}

func (g *GinLogWriter) Write(p []byte) (int, error) {
	g.logFunc(string(p))
	return len(p), nil
}
