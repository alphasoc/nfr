// Package main is main file for namescore.
package main

import (
	"log"
	"os"

	"github.com/alphasoc/namescore/cmd"
)

func main() {
	if err := cmd.NewRootCommand().Execute(); err != nil {
		log.Fatal(err)
	}
}
