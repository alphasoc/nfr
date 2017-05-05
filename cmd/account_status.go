package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/config"
)

func newAccountStatusCommand(configPath *string) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "status",
		Short: "Shows status of namescore",
		Long: `This command return status of current namescore setup.
The following informations are provided:
- API key status`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := config.New(*configPath)
			if err != nil {
				return err
			}

			return accountStatus(cfg)
		},
	}
	return cmd
}

func accountStatus(cfg *config.Config) error {
	c, err := client.New(cfg.Alphasoc.Host, cfg.Alphasoc.APIVersion)
	if err != nil {
		return err
	}
	c.SetKey(cfg.Alphasoc.APIKey)
	status, err := c.AccountStatus()
	if err != nil {
		return err
	}

	fmt.Printf("Account registered: %t\n", status.Registered)
	fmt.Printf("Account expired: %t\n", status.Expired)
	return nil
}
