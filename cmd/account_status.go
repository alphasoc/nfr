package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alphasoc/nfr/client"
)

func newAccountStatusCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "status",
		Short: "Show the status of your AlphaSOC API key and license",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := createConfigAndClient(false)
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
		return fmt.Errorf("get account status failed: %s", err)
	}

	fmt.Printf("Account registered: %t\n", status.Registered)
	fmt.Printf("Account expired: %t\n", status.Expired)
	return nil
}
