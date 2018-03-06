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
	if runtime.GOOS == "windows" {
		configDefaultLocation = path.Join(os.Getenv("APPDATA"), "nfr.data")
	} else {
		configDefaultLocation = "/etc/nfr/config.yml"
	}
}

// NewRootCommand represents the base command when called without any subcommands
func NewRootCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "nfr account|listen|read|version",
		Short: "nfr is main command used to send dns and ip events to AlphaSOC Engine",
		Long: `nfr is an application which captures IP/DNS traffic and provides deep analysis
and alerting of suspicious events, identifying gaps in your security controls and
highlighting targeted attacks.`,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", configDefaultLocation, "Config path for nfr")

	cmd.AddCommand(newVersionCommand())
	cmd.AddCommand(newAccountCommand())
	cmd.AddCommand(newListenCommand())
	cmd.AddCommand(newReadCommand())
	cmd.AddCommand(newMonitorCommand())
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

	c := client.New(cfg.Alphasoc.Host, cfg.Alphasoc.APIKey)
	if checkKey {
		if err := c.CheckKey(); err != nil {
			return nil, nil, err
		}
	}
	return cfg, c, nil
}
