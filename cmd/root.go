package cmd

import (
	"fmt"
	"os"

	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/logger"
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
			cfg, c, err := createConfigAndClient("", false)
			if err != nil {
				return err
			}

			// do not send error to log output, print on console for user
			if err := register(cfg, c, "", ""); err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				os.Exit(1)
			}
			return nil

		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(newVersionCommand())
	cmd.AddCommand(newAccountCommand())
	cmd.AddCommand(newStartCommand())
	cmd.AddCommand(newSendCommand())
	return cmd
}

// createConfigAndClient takes one argument to check if key is active.
func createConfigAndClient(configPath string, checkKey bool) (*config.Config, *client.AlphaSOCClient, error) {
	cfg, err := config.New(configPath)
	if err != nil {
		return nil, nil, err
	}

	if err := logger.SetOutput(cfg.Log.File); err != nil {
		return nil, nil, err
	}
	logger.SetLevel(cfg.Log.Level)

	c := client.New(cfg.Alphasoc.Host, cfg.Alphasoc.APIKey)
	if checkKey {
		if err := c.CheckKey(); err != nil {
			return nil, nil, err
		}
	}
	return cfg, c, nil
}
