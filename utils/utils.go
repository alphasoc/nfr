package utils

import (
	"bufio"
	"fmt"
	"net/mail"
	"os"
	"strings"
)

func emailValidator(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// Details about user.
type Details struct {
	Name  string
	Email string
}

// GetAccountRegisterDetails prompts user for registration data
// like name, email, organizatoin.
func GetAccountRegisterDetails() (*Details, error) {
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

	return &Details{
		Name:  name,
		Email: email,
	}, nil
}

// maximum number of tries for user input before return error.
const maxTries = 2

func getInfo(prompt string, validator func(string) bool) (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("%s: ", prompt)
	for i := maxTries; scanner.Scan() && i > 0; i-- {
		text := scanner.Text()
		if text == "" {
			fmt.Printf("%s can't be blank, try again (%d tries left)\n", prompt, i)
		} else if validator != nil && !validator(text) {
			fmt.Printf("invalid format, try again (%d tries left)\n", i)
		} else {
			return text, nil
		}
		fmt.Printf("%s: ", prompt)
	}
	return "", fmt.Errorf("No input for %s", prompt)
}

// ShadowKey replaces middel of key with dots, so it could be safe
// printed to the console.
func ShadowKey(key string) string {
	l := len(key)
	switch {
	case l == 0:
		return ""
	case l < 3:
		return strings.Repeat(".", 5)
	case l < 10:
		return string(key[0]) + strings.Repeat(".", 5) + string(key[l-1])
	default:
		return key[:3] + strings.Repeat(".", 5) + key[l-3:]
	}
}
