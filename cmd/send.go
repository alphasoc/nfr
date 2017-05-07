package cmd

import (
	"errors"

	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/runner"
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
			cfg, c, err := createConfigAndClient(configPath, true)
			if err != nil {
				return err
			}
			return send(cfg, c, args)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", config.DefaultLocation, "Config path for namescore")
	return cmd
}

func send(cfg *config.Config, c *client.Client, files []string) error {
	for i := range files {
		if _, err := runner.Send(cfg, c, files[i]); err != nil {
			return err
		}
	}
	return nil
}
