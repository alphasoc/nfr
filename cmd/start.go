package cmd

import (
	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/executor"
	"github.com/spf13/cobra"
)

func newStartCommand() *cobra.Command {
	var (
		configPath  string
		offlineMode bool
	)
	var cmd = &cobra.Command{
		Use:   "start",
		Short: "start namescore dns sniffer",
		Long: `Captures DNS traffic and provides analysis of them.
API key must be set before calling this mode.

In --offline mode no requests will be sent to alphasoc, it also
includes that not sending dns queries. In offline mode
it is recomended to set option quries.failed.file in config
to store dns queries, otherwise none of dns quieres will be saved.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, c, err := createConfigAndClient(configPath, !offlineMode)
			if err != nil {
				return err
			}
			return start(c, cfg, offlineMode)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", config.DefaultLocation, "Config path for namescore")
	cmd.Flags().BoolVar(&offlineMode, "offline", false, "Run namescore in offline mode (dns queries would not be sent to AlphaSOC")
	return cmd
}

func start(c client.Client, cfg *config.Config, offlineMode bool) error {
	e, err := executor.New(c, cfg)
	if err != nil {
		return err
	}

	if offlineMode {
		return e.StartOffline()
	}
	return e.Start()
}
