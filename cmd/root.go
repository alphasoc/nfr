package cmd

import (
	"os"
	"path"
	"runtime"

	"github.com/alphasoc/nfr/client"
	"github.com/alphasoc/nfr/config"
	"github.com/alphasoc/nfr/logger"
	"github.com/spf13/cobra"
)

var (
	configDefaultLocation string // default location for config file.
	configPath            string // config path flag
)

func init() {
	base := "/etc/"
	if runtime.GOOS == "windows" {
		base = os.Getenv("APPDATA")
	}
	configDefaultLocation = path.Join(base, "nfr", "config.yml")
}

// NewRootCommand represents the base command when called without any subcommands
func NewRootCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "nfr account|listen|read|version",
		Short: "nfr is main command used to send dns and ip events to AlphaSOC Engine",
		Long: `Network Flight Recorder (NFR) is an application which captures network traffic
and provides deep analysis and alerting of suspicious events, identifying gaps
in your security controls, highlighting targeted attacks and policy violations.`,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.PersistentFlags().StringVarP(&configPath, "config", "c", configDefaultLocation, "Config path for nfr")

	cmd.AddCommand(newVersionCommand())
	cmd.AddCommand(newAccountCommand())
	cmd.AddCommand(newStartCommand())
	cmd.AddCommand(newReadCommand())
	return cmd
}

// createConfigAndClient takes one argument to check if key is active.
func createConfigAndClient(checkKey bool) (*config.Config, *client.AlphaSOCClient, error) {
	cfg, err := config.New(configPath)
	if err != nil {
		return nil, nil, err
	}

	if err := logger.SetOutput(cfg.Log.File); err != nil {
		return nil, nil, err
	}
	logger.SetLevel(cfg.Log.Level)

	c := client.New(cfg.Engine.Host, cfg.Engine.APIKey)
	if checkKey {
		if err := c.CheckKey(); err != nil {
			return nil, nil, err
		}
	}
	return cfg, c, nil
}
