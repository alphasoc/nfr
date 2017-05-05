// Package main is main file for namescore.
package main

import (
	"fmt"
	"os"

	"github.com/alphasoc/namescore/cmd"
)

func main() {
	if err := cmd.NewRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
