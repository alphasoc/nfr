package cmd

import (
	"fmt"

	"github.com/alphasoc/namescore/version"
	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version number of namescore",
		RunE:  printversion,
	}
}

func printversion(cmd *cobra.Command, args []string) error {
	fmt.Printf("namescore version %s\n", version.Version)
	return nil
}
