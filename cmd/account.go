package cmd

import (
	"github.com/alphasoc/namescore/config"
	"github.com/spf13/cobra"
)

func newAccountCommand() *cobra.Command {
	var configPath string
	var cmd = &cobra.Command{
		Use:   "account",
		Short: "Manage AlphaSOC account",
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", config.DefaultLocation, "Config path for namescore")
	cmd.AddCommand(newAccountStatusCommand(&configPath))
	cmd.AddCommand(newAccountRegisterCommand(&configPath))
	cmd.AddCommand(newAccountKeyResetCommand(&configPath))
	return cmd
}
