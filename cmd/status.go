package cmd

import (
	"fmt"
	"namescore/AlphaSocAPI"
	"namescore/config"
	"namescore/daemon"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Shows status of namescore",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: status,
}

func status(cmd *cobra.Command, args []string) {
	fmt.Println("namescore status:")
	fmt.Println()
	cfg := config.Get()

	if cfg.ConfigFileExists() == false {
		fmt.Println("error: no config file present")
		return
	}

	if cfg.ReadFromFile() != nil {
		fmt.Println("error: failed to read configuration file")
		return
	}

	key := cfg.APIKey
	if key == "" {
		fmt.Println("error: no API key set.")
		fmt.Println("Please create new with \"namescore register\"")
		return
	} else if AlphaSocAPI.VerifyKey(key) == false {
		fmt.Println("error: API key does not meet requirements.")
		return
	} else {
		fmt.Println("API key present")
	}

	client := AlphaSocAPI.Client{Server: cfg.GetAlphaSocAddress()}
	client.SetKey(key)

	status, err := client.AccountStatus()
	if err != nil {
		fmt.Println("error: Failed to check account status")
	}

	fmt.Println("Account registered:", status.Registered)
	fmt.Println("Account expired:", status.Expired)

	if daemon.LockSocket() != nil {
		fmt.Println("namescore is running")
	} else {
		fmt.Println("namescore is not running")
	}

}

func init() {
	RootCmd.AddCommand(statusCmd)
}
