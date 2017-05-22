package main

import (
	"fmt"
	"os"

	"github.com/alphasoc/namescore/cmd"
)

func main() {
	if err := cmd.NewRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
}
