// package logger provides functions to configure global logger behaviour.
package logger

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/alphasoc/namescore/utils"
)

var (
	outlog  *os.File
	outpath string
)

// SetOutput sets output for global logger.
func SetOutput(file string) error {
	var (
		f   *os.File
		err error
	)
	f, err = utils.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("can't set logger output: %s", err)
	}
	log.SetOutput(f)
	if outlog != nil && outlog != os.Stdout && outlog != os.Stderr {
		outlog.Close()
	}
	outlog = f
	outpath = file
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
