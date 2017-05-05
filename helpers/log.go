package helpers

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

// SetLogOutput sets output for global logger.
func SetLogOutput(path string) error {
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

// ReloadLogOutput reopen output for global logger.
func ReloadLogOutput() error {
	if outpath != "" {
		return SetLogOutput(outpath)
	}
	return nil
}

// InstallSIGHUPForLog install handler for HUP singal
// Handler will reopen log file.
func InstallSIGHUPForLog() {
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		for {
			if err := ReloadLogOutput(); err != nil {
				log.Print(err)
			}
		}
	}()
}
