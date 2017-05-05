package cmd

import (
	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/helpers"
	"github.com/alphasoc/namescore/runner"
	"github.com/spf13/cobra"
)

func newStartCommand() *cobra.Command {
	var configPath string
	var cmd = &cobra.Command{
		Use:   "start",
		Short: "start namescore dns sniffer",
		Long: `Captures DNS traffic and provides analysis of them.
API key must be set before calling this mode.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := config.New(configPath)
			if err != nil {
				return err
			}
			c, err := client.NewWithKey(cfg.Alphasoc.Host, cfg.Alphasoc.APIVersion, cfg.Alphasoc.APIKey)
			if err != nil {
				return err
			}
			return start(cfg, c)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", config.DefaultLocation, "Config path for namescore")
	return cmd
}

func start(cfg *config.Config, c *client.Client) error {
	// check if key is correct
	if _, err := c.AccountStatus(); err != nil {
		return err
	}

	if err := helpers.SetLogOutput(cfg.Log.File); err != nil {
		return err
	}
	helpers.InstallSIGHUPForLog()

	return runner.Start(cfg, c)
}
