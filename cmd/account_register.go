package cmd

import (
	"fmt"
	"os"

	"github.com/alphasoc/nfr/client"
	"github.com/alphasoc/nfr/config"
	"github.com/alphasoc/nfr/utils"
	"github.com/spf13/cobra"
)

func newAccountRegisterCommand() *cobra.Command {
	var (
		key string
		cmd = &cobra.Command{
			Use:   "register",
			Short: "Generate an API key via the licensing server",
			Long:  "This command provides interactive API key generation and registration.",
			RunE: func(cmd *cobra.Command, args []string) error {
				cfg, err := config.New()
				if err != nil {
					return err
				}
				c := client.New(cfg.Engine.Host, cfg.Engine.APIKey)

				// do not send error to log output, print on console for user
				if err := register(cfg, c, configPath, key); err != nil {
					fmt.Fprintf(os.Stderr, "%s\n", err)
					os.Exit(1)
				}
				return nil
			},
		}
	)
	cmd.Flags().StringVar(&key, "key", "", "AlphaSOC API key")
	return cmd
}

func register(cfg *config.Config, c *client.AlphaSOCClient, configPath, key string) error {
	if key != "" {
		c.SetKey(key)
		fmt.Printf("Using key %s for registration\n", utils.ShadowKey(key))
	} else if cfg.Engine.APIKey != "" {
		c.SetKey(cfg.Engine.APIKey)
		fmt.Printf("Using key %s for registration\n", utils.ShadowKey(cfg.Engine.APIKey))
	}

	if status, err := c.AccountStatus(); err == nil && status.Registered {
		return fmt.Errorf("Account is already registered")
	}

	fmt.Println(`Please provide your details to generate an AlphaSOC API key.
A valid email address is required for activation purposes.

By performing this request you agree to our Terms of Service and Privacy Policy
(https://www.alphasoc.com/terms-of-service)
`)
	details, err := utils.GetAccountRegisterDetails()
	if err != nil {
		return err
	}

	if key == "" && cfg.Engine.APIKey == "" {
		keyReq, err := c.KeyRequest()
		if err != nil {
			fmt.Fprintln(os.Stderr)
			return err
		}
		c.SetKey(keyReq.Key)
		cfg.Engine.APIKey = keyReq.Key
	}

	var errSave error
	if configPath == "" {
		errSave = cfg.Save(configDefaultLocation)
	} else {
		errSave = cfg.Save(configPath)
	}
	if errSave != nil {
		fmt.Fprintf(os.Stderr, `
Unable to create /etc/nfr/config.yml. Please manually set up the directory and configuration file.

alphasoc:
  api_key: %s

`, cfg.Engine.APIKey)
	} else {
		fmt.Println("\nSuccess! The configuration has been written to /etc/nfr/config.yml")
	}

	req := &client.AccountRegisterRequest{Details: struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}{
		Name:  details.Name,
		Email: details.Email,
	}}
	if err := c.AccountRegister(req); err != nil {
		if errSave != nil {
			fmt.Fprintf(os.Stderr, `We were unable to register your account. Please run nfr again with following command:

$ nfr account register --key %s
`, cfg.Engine.APIKey)
			return err
		}

		fmt.Fprintf(os.Stderr, `We were unable to register your account. Please run nfr again with following command:

$ nfr account register
`)
		return err
	}

	fmt.Println("Next, check your email and click the verification link to activate your API key.")
	return nil
}
