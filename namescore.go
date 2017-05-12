package main

import (
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/alphasoc/namescore/cmd"
)

func main() {
	if err := cmd.NewRootCommand().Execute(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
