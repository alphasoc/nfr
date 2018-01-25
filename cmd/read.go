package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/alphasoc/nfr/client"
	"github.com/alphasoc/nfr/config"
	"github.com/alphasoc/nfr/executor"
	"github.com/alphasoc/nfr/utils"
	"github.com/spf13/cobra"
)

var (
	fileFormats  = []string{"bro", "pcap", "suricata"}
	analyzeTypes = []string{"dns", "ip"}
)

func newReadCommand() *cobra.Command {
	var (
		configPath string
		fileFormat string
		fileType   string
	)

	var cmd = &cobra.Command{
		Use:   "read",
		Short: "Process network events stored on disk in known formats",
		Long: `Read file in pcap fromat and send DNS queries to AlphaSOC for analyze
The queries could be save to file via tools like tcpdump, bro or suricata.
See nfr read --help for more informations.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if fileFormat == "" {
				return errors.New("file format required")
			}

			if !utils.StringsContains(fileFormats, fileFormat) {
				return fmt.Errorf("unknown %s file format", fileFormat)
			}

			if len(args) == 0 {
				return errors.New("at least 1 file required")
			}

			cfg, c, err := createConfigAndClient(configPath, true)
			if err != nil {
				return err
			}
			return send(cfg, c, fileFormat, fileType, args)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", configDefaultLocation, "Config path for nfr")
	cmd.Flags().StringVarP(&fileFormat, "format", "f", "pcap", fmt.Sprintf("One of %s file format", sprintSlice(fileFormats)))
	cmd.Flags().StringVar(&fileType, "type", "dns", fmt.Sprintf("One of %s type to analyze", sprintSlice(analyzeTypes)))
	return cmd
}

func send(cfg *config.Config, c client.Client, fileFormat, fileType string, files []string) error {
	e, err := executor.New(c, cfg)
	if err != nil {
		return err
	}

	for i := range files {
		if err := e.Send(files[i], fileFormat, fileType); err != nil {
			return err
		}
		if err := os.Rename(files[i], files[i]+"."+time.Now().Format(time.RFC3339)); err != nil {
			return err
		}
		log.Infof("file %s sent\n", files[i])
	}
	return nil
}

// sprintSlice is a helper to pretty print slice in command help.
func sprintSlice(s []string) string {
	ret := fmt.Sprintf("%s", s)
	return strings.Replace(ret, " ", "|", -1)
}
