package cmd

import (
	"namescore/config"
	"namescore/dns"
	"namescore/utils"
	"os"

	"namescore/asoc"

	"time"

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
	log := utils.Newlog()
	defer log.Close()

	if utils.IsRoot() == false {
		log.Warning("daemon was not started with root privileges.")
		os.Exit(1)
	}

	cfg := config.Get()
	if cfg.ConfigFileExists() == false {
		log.Warning("No configuration file present.")
		os.Exit(1)
	}

	if err := cfg.ReadFromFile(); err != nil {
		log.Warning("Failed to read config: " + err.Error())
		os.Exit(1)
	}

	client := asoc.Client{Server: cfg.GetAlphaSocAddress()}
	client.SetKey(cfg.APIKey)

	s, err := dns.Start(cfg.NetworkInterface)
	if err != nil {
		log.Warning("Failed to start sniffer " + err.Error())
		os.Exit(1)
	}
	log.Info("namescore daemon started")

	//gorutine for event retrieving
	go func() {
		alertStore, err := asoc.OpenAlerts(cfg.GetAlertFilePath())
		if err != nil {
			log.Warning("Failed to open alert file: " + err.Error())
			return
		}
		defer alertStore.Close()

		follow := asoc.ReadFollow(cfg.GetFollowFilePath())

		for {
			if r, err := client.Events(follow); err == nil {
				alertStore.Write(r.Strings())
				alertStore.Flush()
				follow = r.Follow
			}
			time.Sleep(time.Second * cfg.GetAlertRequestInterval())
		}
	}()

	send := func(e []asoc.Entry) {
		if len(e) == 0 {
			return
		}
		if err := client.Queries(asoc.QueriesReq{Data: e}); err != nil {
			//errorhandling
		}
	}

	var container []asoc.Entry
	for {
		dns := s.GetDNS()
		container = append(container, dns...)
		if len(container) > cfg.GetSendIntervalAmount() {
			go send(container)
			container = nil
		}
	}

}
