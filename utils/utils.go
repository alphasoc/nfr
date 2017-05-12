package utils

import (
	"bufio"
	"fmt"
	"net/mail"
	"os"

	"github.com/alphasoc/namescore/client"
)

func emailValidator(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// GetAccountRegisterDetails prompts user for registartion data
// like name, email, organizatoin.
func GetAccountRegisterDetails() (*client.AccountRegisterRequest, error) {
	name, err := getInfo("Full Name", nil)
	if err != nil {
		return nil, err
	}

	email, err := getInfo("Email", emailValidator)
	if err != nil {
		return nil, err
	}

	address, err := mail.ParseAddress(email)
	if err != nil {
		return nil, err
	}
	email = address.Address

	var req client.AccountRegisterRequest
	req.Details.Name = name
	req.Details.Email = email
	return &req, nil
}

// maximum number of tries for user input before return error.
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
