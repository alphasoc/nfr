package cmd

import (
	"fmt"

	"github.com/alphasoc/namescore/helpers"
	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version",
		RunE:  version,
	}
}

func version(cmd *cobra.Command, args []string) error {
	fmt.Printf("namescore version %s\n", helpers.Version)
	return nil
}
