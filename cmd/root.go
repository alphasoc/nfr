package cmd

import (
	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/helpers"
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
			return register(cfg, c, "", "")
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
func createConfigAndClient(configPath string, checkKey bool) (*config.Config, *client.Client, error) {
	cfg, err := config.New(configPath)
	if err != nil {
		return nil, nil, err
	}
	if err := helpers.SetLogOutput(cfg.Log.File); err != nil {
		return nil, nil, err
	}
	c, err := client.NewWithKey(cfg.Alphasoc.Host, cfg.Alphasoc.APIVersion, cfg.Alphasoc.APIKey)
	if err != nil {
		return nil, nil, err
	}
	if checkKey {
		if err := c.CheckKey(); err != nil {
			return nil, nil, err
		}
	}
	return cfg, c, nil
}
