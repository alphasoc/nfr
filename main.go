package main

import (
	"fmt"
	"os"

	"github.com/alphasoc/nfr/cmd"
)

func main() {
	if err := cmd.NewRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
