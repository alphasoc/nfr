package cmd

import (
	"log/syslog"
	"os"
	"time"

	"github.com/alphasoc/namescore/internal/asoc"
	"github.com/alphasoc/namescore/internal/config"
	"github.com/alphasoc/namescore/internal/dns"
	log "github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
)

// listenCmd represents the listen command
var listenCmd = &cobra.Command{
	Use:   "listen",
	Short: "daemon mode",
	Long: `Captures DNS traffic and provides analysis of them.
API key must be set before calling this mode.
`,
	Run: listen,
}

func init() {
	RootCmd.AddCommand(listenCmd)
}

func listen(cmd *cobra.Command, args []string) {
	logger := log.New()
	if sysloghandler, err := log.SyslogHandler(syslog.LOG_USER|syslog.LOG_ERR, "namescore/listen", log.TerminalFormat()); err != nil {
		logger.SetHandler(log.DiscardHandler())
	} else {
		logger.SetHandler(sysloghandler)
	}

	cfg := config.Get()
	if err := cfg.ReadFromFile(); err != nil {
		logger.Warn("Failed to read config", "err", err)
		os.Exit(1)
	}

	if cfg.APIKey == "" {
		logger.Warn("API key not set.")
		os.Exit(1)
	}

	client := asoc.Client{Server: cfg.GetAlphaSocAddress()}
	client.SetKey(cfg.APIKey)

	s, err := dns.Start(cfg.NetworkInterface)
	if err != nil {
		logger.Warn("Failed to start sniffer", "err", err)
		os.Exit(1)
	}
	logger.Info("namescore daemon started")

	//gorutine for event retrieving
	go func() {
		alertStore, err := asoc.OpenAlerts(cfg.GetAlertFilePath())
		if err != nil {
			logger.Warn("Failed to open alert file", "err", err)
			return
		}
		defer alertStore.Close()

		follow := asoc.ReadFollow(cfg.GetFollowFilePath())

		for {
			if r, err := client.Events(follow); err == nil {
				alertStore.Write(r.Strings())
				follow = r.Follow
			}
			time.Sleep(time.Second * cfg.GetAlertRequestInterval())
		}
	}()

	send := func(e []*asoc.Entry) {
		if len(e) == 0 {
			return
		}
		if _, err := client.Queries(&asoc.QueriesReq{Data: e}); err != nil {
			//errorhandling
		}
	}

	var container []*asoc.Entry
	for {
		dns := s.GetDNS()
		container = append(container, dns...)
		if len(container) > cfg.GetSendIntervalAmount() {
			go send(container)
			container = nil
		}
	}

}
