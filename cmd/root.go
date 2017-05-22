package cmd

import (
	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/logger"
	"github.com/spf13/cobra"
)

// NewRootCommand represents the base command when called without any subcommands
func NewRootCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "namescore account|send|start",
		Short: "namescore is main command used to send dns queries to AlphaSOC API",
		Long: `namescore is application which captures DNS requests and provides deep analysis
and alerting of suspicious events, identifying gaps in your security controls and
highlighting targeted attacks.`,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(newVersionCommand())
	cmd.AddCommand(newAccountCommand())
	cmd.AddCommand(newListenCommand())
	cmd.AddCommand(newReadCommand())
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
