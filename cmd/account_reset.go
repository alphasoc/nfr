package cmd

import (
	"fmt"
	"net/mail"

	"github.com/alphasoc/nfr/client"
	"github.com/spf13/cobra"
)

func newAccountKeyResetCommand() *cobra.Command {
	var configPath string
	var cmd = &cobra.Command{
		Use:   "reset",
		Short: "Reset the API key associated with a given email address",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("email is required")
			}

			address, err := mail.ParseAddress(args[0])
			if err != nil {
				return fmt.Errorf("invalid email %s", args[0])
			}

			_, c, err := createConfigAndClient(configPath, false)
			if err != nil {
				return err
			}

			return accountKeyReset(c, address.Address)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", configDefaultLocation, "Config path for nfr")
	return cmd
}

func accountKeyReset(c client.Client, email string) error {
	if err := c.KeyReset(&client.KeyResetRequest{Email: email}); err != nil {
		return err
	}

	fmt.Println("Check your email and click the reset link to get new API key")
	return nil
}
