package dns

import (
	"namescore/asoc"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
#include <arpa/inet.h>
*/
import "C"

type Sniffer struct {
	iface  string
	fd     int
	buffer []byte
}

func Start(iface string) (s *Sniffer, err error) {
	if _, err = net.InterfaceByName(iface); err != nil {
		return nil, err
	}

	s = &Sniffer{}

	s.fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(C.htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}

	err = syscall.BindToDevice(s.fd, iface)
	if err != nil {
		syscall.Close(s.fd)
		return nil, err
	}

	s.buffer = make([]byte, 65536)

	return s, nil
}

func (s *Sniffer) GetDNS() []asoc.Entry {
	for {
		if _, _, err := syscall.Recvfrom(s.fd, s.buffer, 0); err != nil {
			continue
		}

		packet := gopacket.NewPacket(s.buffer, layers.LayerTypeEthernet, gopacket.Default)
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			continue
		}

		dns, _ := dnsLayer.(*layers.DNS)
		if dns.QR {
			continue
		}

		//todo IPv6 test
		var IP string
		if IP4layer := packet.Layer(layers.LayerTypeIPv4); IP4layer != nil {
			ip, _ := IP4layer.(*layers.IPv4)
			IP = ip.SrcIP.String()
		} else if IP6layer := packet.Layer(layers.LayerTypeIPv6); IP6layer != nil {
			ip, _ := IP6layer.(*layers.IPv6)
			IP = ip.SrcIP.String()
		}

		IP4layer := packet.Layer(layers.LayerTypeIPv4)
		if IP4layer == nil {
			continue
		}

		r := make([]asoc.Entry, len(dns.Questions))
		t := time.Now().Format(time.RFC3339)

		for i := range dns.Questions {
			r[i][0] = t
			r[i][1] = IP
			r[i][2] = dns.Questions[i].Type.String()
			r[i][3] = string(dns.Questions[i].Name)
		}

		return r
	}
}

func (s *Sniffer) Close() error {
	if s.fd == 0 {
		return nil
	}
	return syscall.Close(s.fd)
}
