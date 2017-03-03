package cmd

import (
	"fmt"
	"os"

	"github.com/alphasoc/namescore/asoc"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/utils"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Shows status of namescore",
	Long: `This command return status of current namescore setup.
Following informations are provided:
- If configuration is correct.
- API key status.
- State of namescore process .`,
	Run: status,
}

func init() {
	RootCmd.AddCommand(statusCmd)
}

func status(cmd *cobra.Command, args []string) {
	cfg := config.Get()
	fmt.Printf(" Namescore version:        ")
	fmt.Println(aurora.Bold(cfg.Version))

	fmt.Printf(" Configuration status:     ")
	if exist, err := cfg.ConfigFileExists(); err != nil {
		fmt.Println(aurora.Bold((aurora.Red(err))))
		os.Exit(1)
	} else if !exist {
		fmt.Println(aurora.Bold(aurora.Red("not exist")))
		os.Exit(1)
	}
	if err := cfg.ReadFromFile(); err != nil {
		fmt.Println(aurora.Bold((aurora.Red(err))))
		os.Exit(1)
	}
	fmt.Printf("%s ", aurora.Bold(aurora.Green(cfg.ConfigFilePath)))
	fmt.Println(aurora.Bold(aurora.Green("OK")))

	fmt.Printf(" Whitelist file:           ")
	if exist, err := utils.FileExists(cfg.WhitelistFilePath); err != nil {
		fmt.Printf("%s ", aurora.Bold(aurora.Red(cfg.WhitelistFilePath)))
		fmt.Println(aurora.Red(aurora.Bold(err)))
	} else if !exist {
		fmt.Printf("%s ", aurora.Bold(aurora.Red(cfg.WhitelistFilePath)))
		fmt.Println(aurora.Bold(aurora.Red("not exist")))
	} else {
		fmt.Printf("%s ", aurora.Bold(aurora.Green(cfg.WhitelistFilePath)))
		fmt.Println(aurora.Bold(aurora.Green("OK")))
	}

	fmt.Printf(" Alerts file:              ")
	if exist, err := utils.FileExists(cfg.AlertFilePath); err != nil {
		fmt.Printf("%s ", aurora.Bold(aurora.Red(cfg.AlertFilePath)))
		fmt.Println(aurora.Red(aurora.Bold(err)))
	} else if !exist {
		fmt.Printf("%s ", aurora.Bold(aurora.Red(cfg.AlertFilePath)))
		fmt.Println(aurora.Bold(aurora.Red("not exist")))
	} else {
		fmt.Printf("%s ", aurora.Bold(aurora.Green(cfg.AlertFilePath)))
		fmt.Println(aurora.Bold(aurora.Green("OK")))
	}

	fmt.Printf(" Network interface to use: ")
	if cfg.NetworkInterface == "" {
		fmt.Println(aurora.Bold(aurora.Red("not configured")))
	} else {
		fmt.Println(aurora.Bold(aurora.Green(cfg.NetworkInterface)))
	}

	fmt.Printf(" API key status:           ")
	if cfg.APIKey == "" {
		fmt.Println(aurora.Bold(aurora.Red("not set")))
		os.Exit(1)
	} else if !asoc.VerifyKey(cfg.APIKey) {
		fmt.Println(aurora.Bold(aurora.Red("invalid")))
		os.Exit(1)
	} else {
		fmt.Println(aurora.Bold(aurora.Green("valid")))
	}

	client := asoc.NewClient(cfg.AlphaSOCAddress, cfg.Version)
	client.SetKey(cfg.APIKey)

	fmt.Printf(" Connection with AlphaSOC: ")
	status, err := client.AccountStatus()
	if err != nil {
		fmt.Println(aurora.Bold((aurora.Red(err))))
		os.Exit(1)
	}
	fmt.Println(aurora.Bold(aurora.Green("OK")))

	fmt.Printf(" Account registered:       ")
	if status.Registered {
		fmt.Println(aurora.Bold((aurora.Green(status.Registered))))
	} else {
		fmt.Println(aurora.Bold((aurora.Red(status.Registered))))
	}

	fmt.Printf(" Account expired:          ")
	if status.Expired {
		fmt.Println(aurora.Bold((aurora.Red(status.Expired))))
	} else {
		fmt.Println(aurora.Bold((aurora.Green(status.Expired))))
	}

	fmt.Printf(" Namescore daemon:         ")
	if utils.LockSocket() != nil {
		fmt.Println(aurora.Bold(aurora.Green("running")))
	} else {
		fmt.Println(aurora.Bold(aurora.Red("not running")))
	}

}
