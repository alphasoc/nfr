package cmd

import (
	"errors"

	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/helpers"
	"github.com/spf13/cobra"
)

func newSendCommand() *cobra.Command {
	var configPath string
	var cmd = &cobra.Command{
		Use:   "send",
		Short: "send dns queries to AlphaSOC server",
		Long:  `Read file in pcap fromat and send DNS packet to AlphaSOC server`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("at least 1 file required")
			}

			cfg, _, err := config.New(configPath)
			if err != nil {
				return err
			}
			c, err := client.NewWithKey(cfg.Alphasoc.Host, cfg.Alphasoc.APIVersion, cfg.Alphasoc.APIKey)
			if err != nil {
				return err
			}
			return send(cfg)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", config.DefaultLocation, "Config path for namescore")
	return cmd
}

func start(cfg *config.Config, c *client.Client, files []string) error {
	// check if key is correct
	if _, err := c.AccountStatus(); err != nil {
		return err
	}

	if err := helpers.SetLogOutput(cfg.Log.File); err != nil {
		return err
	}

	return runner.Send(c, files)
}
