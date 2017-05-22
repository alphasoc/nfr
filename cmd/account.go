package cmd

import "github.com/spf13/cobra"

func newAccountCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "account",
		Short: "Manage AlphaSOC account",
	}
	cmd.AddCommand(newAccountStatusCommand())
	cmd.AddCommand(newAccountRegisterCommand())
	cmd.AddCommand(newAccountKeyResetCommand())
	return cmd
}
