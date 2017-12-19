package cmd

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/alphasoc/nfr/client"
	"github.com/alphasoc/nfr/config"
	"github.com/alphasoc/nfr/executor"
	"github.com/spf13/cobra"
)

// formats must be sorted
var fileFormats = []string{"bro", "pcap", "suricata"}

func newReadCommand() *cobra.Command {
	var (
		configPath string
		fileFormat string
	)

	var cmd = &cobra.Command{
		Use:   "read",
		Short: "Process DNS events stored on disk in known formats",
		Long: `Read file in pcap fromat and send DNS queries to AlphaSOC for analyze
The queries could be save to file via tools like tcpdump.
See nfr read --help for more informations.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if sort.SearchStrings(fileFormats, fileFormat) == len(fileFormats) {
				return fmt.Errorf("unknown %s file format", fileFormat)
			}

			if len(args) == 0 {
				return errors.New("at least 1 file required")
			}

			cfg, c, err := createConfigAndClient(configPath, true)
			if err != nil {
				return err
			}
			return send(cfg, c, fileFormat, args)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", config.DefaultLocation, "Config path for nfr")
	cmd.Flags().StringVarP(&fileFormat, "format", "f", fileFormats[0], fmt.Sprintf("One of %s file format", sprintFileFormats()))
	return cmd
}

func send(cfg *config.Config, c client.Client, fileFormat string, files []string) error {
	e, err := executor.New(c, cfg)
	if err != nil {
		return err
	}

	for i := range files {
		if err := e.Send(files[i], fileFormat); err != nil {
			return err
		}
		if err := os.Rename(files[i], files[i]+"."+time.Now().Format(time.RFC3339)); err != nil {
			return err
		}
		log.Infof("file %s sent\n", files[i])
	}
	return nil
}

// sprintFileFormats is a helper to pretty print file formats in command help.
func sprintFileFormats() string {
	s := fmt.Sprintf("%s", fileFormats)
	return strings.Replace(s, " ", "|", -1)
}
