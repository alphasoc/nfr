package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/alphasoc/namescore/asoc"
	"github.com/alphasoc/namescore/config"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/cobra"
)

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Acquire and register API key.",
	Long:  `This command provides interactive mode to retrieve API key and register it.`,
	Run:   register,
}

func init() {
	RootCmd.AddCommand(registerCmd)
}

// errNoInput appears when user does not provide input for mandatory variable.
var errNoInput = errors.New("invalid user input")

func register(cmd *cobra.Command, args []string) {
	fmt.Println(aurora.Bold("API key registration."))
	cfg := config.Get()
	client := asoc.Client{Server: cfg.AlphaSOCAddress, Version: cfg.Version}

	if err := cfg.ReadFromFile(); err == nil {
		if asoc.VerifyKey(cfg.APIKey) {
			fmt.Println("Found valid API key.")
			client.SetKey(cfg.APIKey)
			status, err := client.AccountStatus()
			if err != nil {
				fmt.Println(aurora.Bold(aurora.Red("Failed to check account status:")))
				fmt.Println(aurora.Bold((aurora.Red(err))))
				os.Exit(1)
			}
			if status.Registered {
				fmt.Println(aurora.Bold(aurora.Green("Account is already registered.")))
				os.Exit(0)
			}
		}
	}

	if cfg.NetworkInterface == "" {
		iface, err := defaultUserInput().get("Network interface to bind with: ", true)
		if err != nil {
			fmt.Println()
			fmt.Println(aurora.Bold(aurora.Red("error:")))
			fmt.Println(aurora.Bold((aurora.Red(err))))
			os.Exit(1)
		}
		cfg.NetworkInterface = iface
	}

	data, err := readRegisterData(defaultUserInput())
	fmt.Println()
	if err != nil {
		fmt.Println(aurora.Bold(aurora.Red("error:")))
		fmt.Println(aurora.Bold((aurora.Red(err))))
		os.Exit(1)
	}

	if cfg.APIKey == "" {
		key, err := client.KeyRequest()
		if err != nil {
			fmt.Println(aurora.Bold(aurora.Red("Failed to get new API key from server:")))
			fmt.Println(aurora.Bold((aurora.Red(err))))
			os.Exit(1)
		}
		cfg.APIKey = key
	}
	client.SetKey(cfg.APIKey)

	if err := cfg.InitialDirsCreate(); err != nil {
		fmt.Println(aurora.Bold(aurora.Red("Failed to create directories for namescore")))
		fmt.Println(aurora.Bold((aurora.Red(err))))
		os.Exit(1)
	}

	if err := cfg.SaveToFile(); err != nil {
		fmt.Println(aurora.Bold(aurora.Red("Failed to save config file")))
		fmt.Println(aurora.Bold((aurora.Red(err))))
		os.Exit(1)
	}

	if err := client.Register(data); err != nil {
		fmt.Println(aurora.Bold(aurora.Red("Failed to register account:")))
		fmt.Println(aurora.Bold((aurora.Red(err))))
		os.Exit(1)
	}
	fmt.Println(aurora.Bold(aurora.Green("Account was successfully registered.")))
}

type userInput struct {
	reader  io.Reader
	writer  io.Writer
	scanner *bufio.Scanner
}

func defaultUserInput() *userInput {
	u := &userInput{reader: os.Stdin, writer: os.Stdout}
	u.scanner = bufio.NewScanner(u.reader)
	return u
}

func (u *userInput) get(text string, mandatory bool) (string, error) {
	if _, err := fmt.Fprintf(u.writer, "%s", text); err != nil {
		return "", err
	}
	u.scanner.Scan()
	line := u.scanner.Text()

	if err := u.scanner.Err(); err != nil {
		return "", err
	}

	if mandatory && line == "" {
		return "", errNoInput
	}
	return line, nil
}

func readRegisterData(userIn *userInput) (rq *asoc.RegisterReq, err error) {

	fmt.Fprintln(userIn.writer, "Provide necessary data for API key registration.")

	rq = &asoc.RegisterReq{}

	if rq.Details.Name, err = userIn.get("Name: ", true); err != nil {
		return nil, err
	}

	if rq.Details.Organization, err = userIn.get("Organization: ", true); err != nil {
		return nil, err
	}

	if rq.Details.Email, err = userIn.get("email: ", true); err != nil {
		return nil, err
	}

	if rq.Details.Phone, err = userIn.get("phone: ", true); err != nil {
		return nil, err
	}

	if rq.Details.Address[0], err = userIn.get("Address (1/3): ", true); err != nil {
		return nil, err
	}

	if rq.Details.Address[1], err = userIn.get("Address (2/3): ", false); err != nil {
		return nil, err
	}

	if rq.Details.Address[2], err = userIn.get("Address (3/3): ", false); err != nil {
		return nil, err
	}

	return rq, nil
}
