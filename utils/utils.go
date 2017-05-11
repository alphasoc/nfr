package utils

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/alphasoc/namescore/client"
	"github.com/asaskevich/govalidator"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DecodePackets into api Queries request.
// Packtes that has diffrent header then DNS are droped.
func DecodePackets(packets []gopacket.Packet) *client.QueriesRequest {
	qr := client.QueriesRequest{Data: make([][4]string, 0, len(packets))}

	for i := range packets {
		ldns, ok := packets[i].ApplicationLayer().(gopacket.Layer).(*layers.DNS)
		if !ok || ldns.QR {
			continue
		}

		md := packets[i].Metadata()
		if md == nil {
			continue
		}

		var srcIP net.IP
		if lipv4, ok := packets[i].TransportLayer().(gopacket.Layer).(*layers.IPv4); ok {
			srcIP = lipv4.SrcIP
		} else if lipv6, ok := packets[i].TransportLayer().(gopacket.Layer).(*layers.IPv6); ok {
			srcIP = lipv6.SrcIP
		} else {
			continue
		}

		for _, q := range ldns.Questions {
			qr.Data = append(qr.Data, [4]string{
				md.Timestamp.Format(time.RFC3339),
				srcIP.String(),
				q.Type.String(),
				string(q.Name),
			})
		}
	}
	return nil
}

// GetAccountRegisterDetails prompts user for registartion infos
// like name, email, organizatoin.
func GetAccountRegisterDetails() (*client.AccountRegisterRequest, error) {
	name, err := getInfo("Full Name", nil)
	if err != nil {
		return nil, err
	}

	email, err := getInfo("Email", govalidator.IsEmail)
	if err != nil {
		return nil, err
	}
	organization, err := getInfo("Organization", nil)
	if err != nil {
		return nil, err
	}

	var req client.AccountRegisterRequest
	req.Details.Name = name
	req.Details.Email = email
	req.Details.Organization = organization
	return &req, nil
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
