package cmd

import (
	"fmt"

	"github.com/alphasoc/nfr/version"
	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the NFR binary version",
		RunE:  printversion,
	}
}

func printversion(cmd *cobra.Command, args []string) error {
	fmt.Printf("nfr version %s\n", version.Version)
	return nil
}
