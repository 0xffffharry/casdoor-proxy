package log

type SimpleWriter struct {
	logger    LoggerInterface
	printFunc func(a ...any)
}

func NewSimpleWriter(logger LoggerInterface, level logLevel) *SimpleWriter {
	s := &SimpleWriter{logger: logger}
	switch level {
	case InfoLevel:
		s.printFunc = logger.Info
	case WarnLevel:
		s.printFunc = logger.Warn
	case ErrorLevel:
		s.printFunc = logger.Error
	case FatalLevel:
		s.printFunc = logger.Fatal
	case DebugLevel:
		s.printFunc = logger.Debug
	default:
		s.printFunc = logger.Info
	}
	return s
}

func (s *SimpleWriter) Write(p []byte) (n int, err error) {
	s.printFunc(string(p))
	return len(p), nil
}
