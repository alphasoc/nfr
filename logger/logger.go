package logger

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var (
	outlog  *os.File
	outpath string
)

// SetOutput sets output for global logger.
func SetOutput(path string) error {
	var (
		f   *os.File
		err error
	)

	if path == "stdout" {
		f = os.Stdout
	} else if path == "stderr" {
		f = os.Stderr
	} else {
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("can't set logger output: %s", err)
		}
	}
	log.SetOutput(f)
	if outlog != nil && outlog != os.Stdout && outlog != os.Stderr {
		outlog.Close()
	}
	outlog = f
	outpath = path
	return nil
}

// Reload reopen output for global logger.
func Reload() error {
	if outpath != "" {
		return SetOutput(outpath)
	}
	return nil
}

// InstallSIGHUP install handler for HUP singal, that will reopen log file.
func InstallSIGHUP() {
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		for {
			if err := Reload(); err != nil {
				log.Print(err)
			}
		}
	}()
}
