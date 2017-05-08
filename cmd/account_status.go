package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alphasoc/namescore/client"
)

func newAccountStatusCommand(configPath *string) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "status",
		Short: "Shows status of namescore",
		Long: `This command return status of current namescore setup.
The following informations are provided:
- API key status`,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := createConfigAndClient(*configPath, false)
			if err != nil {
				return err
			}

			return accountStatus(c)
		},
	}
	return cmd
}

func accountStatus(c client.Client) error {
	status, err := c.AccountStatus()
	if err != nil {
		return err
	}

	fmt.Printf("Account registered: %t\n", status.Registered)
	fmt.Printf("Account expired: %t\n", status.Expired)
	return nil
}
