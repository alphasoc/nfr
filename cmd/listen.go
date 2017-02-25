package cmd

import (
	"log/syslog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alphasoc/namescore/asoc"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/dns"
	"github.com/alphasoc/namescore/utils"
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
	logger := configureLogger(args)

	cfg := config.Get()
	if err := cfg.ReadFromFile(); err != nil {
		logger.Warn("Failed to read config", "err", err)
		os.Exit(1)
	}

	if cfg.APIKey == "" {
		logger.Warn("API key not set.")
		os.Exit(1)
	}

	if err := utils.LockSocket(); err != nil {
		logger.Warn("LockSocket", "err", err)
		os.Exit(1)
	}

	if err := cfg.InitialDirsCreate(); err != nil {
		logger.Warn("Failed to create proper dir structure", "error", err)
		os.Exit(1)
	}

	client := asoc.Client{Server: cfg.AlphaSOCAddress, Version: cfg.Version}
	client.SetKey(cfg.APIKey)

	sniffer, err := dns.Start(cfg.NetworkInterface)
	if err != nil {
		logger.Warn("Failed to start sniffer", "err", err)
		os.Exit(1)
	}

	whitelist, errList := dns.NewWhitelist(cfg.WhitelistFilePath)
	if errList != nil {
		logger.Info("Whitelist error", "err", errList)
	} else {
		sniffer.SetFQDNFilter(whitelist.CheckFqdn)
		sniffer.SetIPFilter(whitelist.CheckIP)
	}

	logger.Info("namescore daemon started", "version", cfg.Version)

	sig := make(chan os.Signal)
	quit := make(chan bool)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

	store := asoc.NewQueryStore(cfg.FailedQueriesLimit, cfg.FailedQueriesDir)

	handler := &listenHandler{
		cfg:        cfg,
		quit:       quit,
		client:     &client,
		logger:     logger,
		sniffer:    sniffer,
		queryStore: store,
	}

	go handler.SniffLoop()
	go handler.QueriesLoop()
	go handler.AlertsLoop()
	go handler.LocalQueriesLoop()

	for {
		s := <-sig
		close(quit)
		// Give namescore some time to close gorutines
		time.Sleep(time.Second * 2)

		logger.Info("namescore exitting", "signal", s.String())
		os.Exit(0)
	}
}

func configureLogger(args []string) log.Logger {
	logger := log.New()
	sysloghandler, err := log.SyslogHandler(syslog.LOG_USER|syslog.LOG_ERR, "namescore/listen", log.TerminalFormat())
	if err != nil {
		logger.SetHandler(log.DiscardHandler())
		return logger
	}

	logger.SetHandler(sysloghandler)
	return logger
}
