package cmd

import (
	"fmt"
	"namescore/config"
	"namescore/dns"
	"namescore/utils"
	"os"

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

	s, err := dns.Start(cfg.NetworkInterface)
	if err != nil {
		log.Warning("Failed to start sniffer " + err.Error())
		os.Exit(1)
	}

	log.Info("namescore daemon started")
	for {
		fmt.Println(s.GetDNS())

	}

}
