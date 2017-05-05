package helpers

import (
	"bufio"
	"fmt"
	"os"

	"github.com/asaskevich/govalidator"
)

// GetAccountRegisterDetails prompts user for registartion infos
// like name, email, organizatoin.
func GetAccountRegisterDetails() (string, string, string, error) {
	name, err := getInfo("Full Name", nil)
	if err != nil {
		return "", "", "", err
	}

	email, err := getInfo("Email", govalidator.IsEmail)
	if err != nil {
		return "", "", "", err
	}
	organization, err := getInfo("Organization", nil)
	if err != nil {
		return "", "", "", err
	}

	return name, email, organization, nil
}

const maxTries = 2

func getInfo(prompt string, validator func(string) bool) (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("%s: ", prompt)
	for i := maxTries; scanner.Scan() && i > 0; i-- {
		text := scanner.Text()
		if text == "" {
			fmt.Printf("%s can't be black, try again (%d tries left)\n", prompt, i)
		} else if validator != nil && !validator(text) {
			fmt.Printf("invalid format, try again (%d tries left)\n", i)
		} else {
			return text, nil
		}
		fmt.Printf("%s: ", prompt)
	}
	return "", fmt.Errorf("No input for %s", prompt)
}
