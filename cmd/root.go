package cmd

import (
	"github.com/alphasoc/namescore/config"
	"github.com/spf13/cobra"
)

// NewRootCommand represents the base command when called without any subcommands
func NewRootCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "namescore listen|register|status",
		Short: "AlphaSOC namescore client.",
		Long: `namescore is application which captures DNS requests and provides
deep analysis and alerting of suspicious events,
identifying gaps in your security controls and highlighting targeted attacks.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := config.New("")
			if err != nil {
				return err
			}
			return register(cfg, "", "")
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(newVersionCommand())
	cmd.AddCommand(newAccountCommand())
	cmd.AddCommand(newListenCommand())
	return cmd
}
