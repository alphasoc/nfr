//todo check apache license

package cmd

import (
	"fmt"
	"log/syslog"
	"namescore/DNSSniffer"
	"namescore/config"
	"namescore/daemon"
	"os"

	"github.com/spf13/cobra"
)

// listenCmd represents the listen command
var listenCmd = &cobra.Command{
	Use:   "listen",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: listen,
}

func init() {
	RootCmd.AddCommand(listenCmd)
}

func listen(cmd *cobra.Command, args []string) {
	l, err := syslog.New(syslog.LOG_USER|syslog.LOG_ERR, "namescore")
	if err != nil {
		fmt.Println("Cannot connect to syslog")
		os.Exit(1)
	}
	defer l.Close()

	if daemon.IsRoot() == false {
		l.Warning("daemon was not started with root privileges.")
		os.Exit(1)
	}

	cfg := config.Get()
	if cfg.ConfigFileExists() == false {
		l.Warning("No configuration file present.")
		os.Exit(1)
	}

	if err := cfg.ReadFromFile(); err != nil {
		l.Warning("Failed to read config: " + err.Error())
		os.Exit(1)
	}

	s, err := DNSSniffer.Start(cfg.NetworkInterface)
	if err != nil {
		l.Warning("Failed to start sniffer " + err.Error())
		os.Exit(1)
	}

	l.Info("daemon started")
	for {
		fmt.Println(s.GetDNS())

	}

	// to discuss
}
