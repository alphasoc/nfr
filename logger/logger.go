// package logger provides functions to configure global logger behaviour.
package logger

import (
	"fmt"
	"os"

	log "github.com/Sirupsen/logrus"
)

// SetOutput sets output for global logger.
func SetOutput(file string) error {
	switch file {
	case "stdout":
		log.SetOutput(os.Stdout)
	case "stderr":
		log.SetOutput(os.Stderr)
	default:
		f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("can't set logger output: %s", err)
		}
		log.SetOutput(f)
	}
	return nil
}

func SetLevel(level string) {
	switch level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
}
