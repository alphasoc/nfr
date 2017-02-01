package cmd

import (
	"bufio"
	"namescore/AlphaSocAPI"
	"namescore/config"
	"namescore/daemon"

	"fmt"

	"log/syslog"

	"os"

	"github.com/spf13/cobra"
)

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: register,
}

func init() {
	RootCmd.AddCommand(registerCmd)
}

func register(cmd *cobra.Command, args []string) {
	if daemon.IsRoot() == false {
		fmt.Println("This command must be run with root privileges.")
		os.Exit(0)
	}

	l, err := syslog.New(syslog.LOG_USER|syslog.LOG_ERR, "namescore")
	if err != nil {
		fmt.Println("Cannot connect to syslog")
		os.Exit(1)
	}
	l.Info("namescore register called")
	defer l.Close()

	cfg := config.Get()
	if cfg.ConfigFileExists() {
		if err := cfg.ReadFromFile(); err != nil {
			logfail(l, err, "Failed to read configuration file.")
		}
	}

	client := AlphaSocAPI.Client{Server: cfg.GetAlphaSocAddress()}
	newKey := false
	if cfg.APIKey == "" {
		key, err := client.KeyRequest()
		if err != nil {
			logfail(l, err, "Failed to get new API key from server.")
		}
		l.Info("New API key retrieved.")
		cfg.APIKey = key
		newKey = true
	}
	client.SetKey(cfg.APIKey)

	if cfg.NetworkInterface == "" {
		fmt.Println("Provide network interface to be used by namescore:")
		cfg.ReadInterface(os.Stdin)
	}

	if err := cfg.SaveToFile(); err != nil {
		logfail(l, err, "Failed to save config file.")
	}

	if newKey == false {
		status, err := client.AccountStatus()
		if err != nil {
			logfail(l, err, "Failed to check account status.")
		}
		if status.Registered == true {
			fmt.Println("Account is already registered.")
			os.Exit(0)
		}
	}

	data := readRegisterData()
	if err := client.Register(data); err != nil {
		logfail(l, err, "Failed to register account")
	}

	fmt.Println("Account was successfully registered.")
}

func logfail(w *syslog.Writer, e error, msg string) {
	fmt.Println(msg)
	w.Warning("register: " + e.Error())
	os.Exit(1)
}

func readRegisterData() *AlphaSocAPI.RegisterReq {
	fmt.Println("Provide necessary data for API key registration.")
	data := AlphaSocAPI.RegisterReq{}
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("Name: ")
	scanner.Scan()
	data.Details.Name = scanner.Text()

	fmt.Printf("Organization: ")
	scanner.Scan()
	data.Details.Organization = scanner.Text()

	fmt.Printf("email: ")
	scanner.Scan()
	data.Details.Email = scanner.Text()

	fmt.Printf("phone: ")
	scanner.Scan()
	data.Details.Phone = scanner.Text()

	fmt.Printf("Address (1/3): ")
	scanner.Scan()
	data.Details.Address[0] = scanner.Text()

	fmt.Printf("Address (2/3): ")
	scanner.Scan()
	data.Details.Address[1] = scanner.Text()

	fmt.Printf("Address (3/3): ")
	scanner.Scan()
	data.Details.Address[2] = scanner.Text()

	return &data
}
