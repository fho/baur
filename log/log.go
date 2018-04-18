package log

import (
	golog "log"
	"os"
)

var (
	stdoutLogger *golog.Logger
	stderrLogger *golog.Logger
	debug        bool
)

func init() {
	stdoutLogger = golog.New(os.Stdout, "", 0)
	stderrLogger = golog.New(os.Stderr, "", 0)
}

// EnableDebug enables or dsisables logging of debug messages
func EnableDebug(activated bool) {
	debug = activated
}

// Debug logs a debug message to stdout.
// It's only shown if debugging is enabled.
func Debug(v ...interface{}) {
	if !debug {
		return
	}

	stdoutLogger.Print(v)
}

// Debugf logs a debug message to stdout.
// It's only shown if debugging is enabled.
func Debugf(format string, v ...interface{}) {
	if !debug {
		return
	}

	stdoutLogger.Printf(format, v)
}

// Error logs a message to stderr
func Error(v ...interface{}) {
	stderrLogger.Print(v)
}

// Errorf logs a message to stderr
func Errorf(format string, v ...interface{}) {
	stderrLogger.Printf(format, v)
}

// Info logs a message to stdout
func Info(v ...interface{}) {
	stdoutLogger.Print(v)
}

// Infof logs a message to stdout
func Infof(format string, v ...interface{}) {
	stdoutLogger.Printf(format, v)
}
