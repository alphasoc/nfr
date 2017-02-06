package cmd

import (
	"bufio"
	"fmt"
	"namescore/asoc"
	"namescore/config"
	"namescore/utils"
	"os"

	"github.com/spf13/cobra"
)

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Acquire and register API key.",
	Long:  `Acquire and register API key.`,
	Run:   register,
}

func init() {
	RootCmd.AddCommand(registerCmd)
}

func register(cmd *cobra.Command, args []string) {
	if utils.IsRoot() == false {
		fmt.Println("This command must be run with root privileges.")
		os.Exit(0)
	}

	log := utils.Newlog()
	defer log.Close()

	log.Infov("namescore register")

	cfg := config.Get()
	if cfg.ConfigFileExists() {
		if err := cfg.ReadFromFile(); err != nil {
			log.Warningv("Failed to read configuration file.", err)
			os.Exit(1)
		}
	}

	client := asoc.Client{Server: cfg.GetAlphaSocAddress()}
	newKey := false
	if cfg.APIKey == "" {
		key, err := client.KeyRequest()
		if err != nil {
			log.Warningv("Failed to get new API key from server.", err)
			os.Exit(1)
		}
		log.Infov("New API key retrieved.")
		cfg.APIKey = key
		newKey = true
	}
	client.SetKey(cfg.APIKey)

	if cfg.NetworkInterface == "" {
		fmt.Println("Provide network interface to be used by namescore:")
		cfg.ReadInterface(os.Stdin)
	}

	if err := cfg.SaveToFile(); err != nil {
		log.Warningv("Failed to save config file.", err)
		os.Exit(1)
	}

	if newKey == false {
		status, err := client.AccountStatus()
		if err != nil {
			log.Warningv("Failed to check account status.", err)
			os.Exit(1)
		}
		if status.Registered == true {
			fmt.Println("Account is already registered.")
			os.Exit(0)
		}
	}

	data := readRegisterData()
	if err := client.Register(data); err != nil {
		log.Warningv("Failed to register account", err)
		os.Exit(1)
	}

	log.Infov("Account was successfully registered.")
}

func readRegisterData() *asoc.RegisterReq {
	fmt.Println("Provide necessary data for API key registration.")
	data := asoc.RegisterReq{}
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
