package cmd

import (
	"fmt"

	"github.com/alphasoc/namescore/client"
	"github.com/spf13/cobra"
)

func newAccountKeyResetCommand(configPath *string) *cobra.Command {
	var email string
	var cmd = &cobra.Command{
		Use:   "key-reset",
		Short: "Reset AlphaSOC API key.",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := createConfigAndClient(*configPath, false)
			if err != nil {
				return err
			}

			return accountKeyReset(c, email)
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "AlphaSOC account email")
	cmd.MarkFlagRequired("email")
	return cmd
}

func accountKeyReset(c *client.Client, email string) error {
	if err := c.KeyReset(&client.KeyResetRequest{Email: email}); err != nil {
		return err
	}

	fmt.Println("Check your email and click the reset link to get new API key")
	return nil
}
