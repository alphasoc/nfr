package dns

import (
	"net"
	"syscall"
	"time"

	"github.com/alphasoc/namescore/internal/asoc"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
#include <arpa/inet.h>
*/
import "C"

type FQDNFilter func(string) bool
type IPFilter func(net.IP) bool

type DNSCapture interface {
	PacketToDNS(rawpacket []byte) []asoc.Entry
	Sniff() []byte
}

type Sniffer struct {
	fd         int
	ipFilter   IPFilter
	fqdnFilter FQDNFilter
}

func Start(iface string) (*Sniffer, error) {
	if _, err := net.InterfaceByName(iface); err != nil {
		return nil, err
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(C.htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}

	err = syscall.BindToDevice(fd, iface)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &Sniffer{fd: fd}, nil
}

func (s *Sniffer) SetFQDNFilter(f FQDNFilter) {
	s.fqdnFilter = f
}

func (s *Sniffer) SetIPFilter(f IPFilter) {
	s.ipFilter = f
}

func (s *Sniffer) Sniff() []byte {
	buffer := make([]byte, 65536)
	for {
		if _, _, err := syscall.Recvfrom(s.fd, buffer, 0); err != nil {
			continue
		}
		return buffer
	}

}

func (s *Sniffer) PacketToDNS(rawpacket []byte) []asoc.Entry {
	packet := gopacket.NewPacket(rawpacket, layers.LayerTypeEthernet, gopacket.Default)
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}

	dns, _ := dnsLayer.(*layers.DNS)
	if dns.QR {
		return nil
	}

	var IP net.IP
	if IP4layer := packet.Layer(layers.LayerTypeIPv4); IP4layer != nil {
		ip, _ := IP4layer.(*layers.IPv4)
		IP = ip.SrcIP
	} else if IP6layer := packet.Layer(layers.LayerTypeIPv6); IP6layer != nil {
		ip, _ := IP6layer.(*layers.IPv6)
		IP = ip.SrcIP
	}

	var entries []asoc.Entry
	t := time.Now()

	for i := range dns.Questions {
		if s.fqdnFilter != nil {
			if s.fqdnFilter(string(dns.Questions[i].Name)) {
				return nil
			}
			if s.ipFilter(IP) {
				return nil
			}
		}
		entries = append(entries, asoc.Entry{Time: t, IP: IP, QType: dns.Questions[i].Type.String(), FQDN: string(dns.Questions[i].Name)})
	}
	return entries
}
