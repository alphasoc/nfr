package cmd

import (
	"fmt"

	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/config"
	"github.com/spf13/cobra"
)

func newAccountKeyResetCommand(configPath *string) *cobra.Command {
	var email string
	var cmd = &cobra.Command{
		Use:   "key-reset",
		Short: "Reset AlphaSOC API key.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := config.New(*configPath)
			if err != nil {
				return err
			}
			return accountKeyReset(cfg, email)
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "AlphaSOC account email")
	cmd.MarkFlagRequired("email")
	return cmd
}

func accountKeyReset(cfg *config.Config, email string) error {
	c, err := client.New(cfg.Alphasoc.Host, cfg.Alphasoc.APIVersion)
	if err != nil {
		return err
	}

	if err := c.KeyReset(&client.KeyResetRequest{Email: email}); err != nil {
		return err
	}

	fmt.Println("Check your email and click the reset link to get new API key")
	return nil
}
