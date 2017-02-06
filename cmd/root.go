package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "test",
	Short: "AlphaSoc namescore client.",
	Long: `namescore is application which captures DNS requests and provides
deep analysis and alerting of suspicious events,
identifying gaps in your security controls and highlighting targeted attacks.`,
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
