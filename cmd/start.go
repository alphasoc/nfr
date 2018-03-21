package cmd

import (
	"github.com/alphasoc/nfr/client"
	"github.com/alphasoc/nfr/config"
	"github.com/alphasoc/nfr/executor"
	"github.com/spf13/cobra"
)

func newStartCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "start",
		Short: "Start processing network events (inputs defined in config)",
		Long:  `Start processing network events. API key must be set before calling this mode.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, c, err := createConfigAndClient(true)
			if err != nil {
				return err
			}
			return start(c, cfg)
		},
	}
	return cmd
}

func start(c client.Client, cfg *config.Config) error {
	e, err := executor.New(c, cfg)
	if err != nil {
		return err
	}
	return e.Start()
}
