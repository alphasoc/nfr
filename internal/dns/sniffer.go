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
	Start(iface string, queriesMax int) (DNSCapture, chan []asoc.Entry, error)
	SetFQDNFilter(FQDNFilter)
	SetIPFilter(IPFilter)
}

type Sniffer struct {
	fd         int
	buffer     []byte
	ready      chan []asoc.Entry
	queriesMax int
	ipFilter   IPFilter
	fqdnFilter FQDNFilter
}

func Start(iface string, queriesMax int) (*Sniffer, chan []asoc.Entry, error) {
	if _, err := net.InterfaceByName(iface); err != nil {
		return nil, nil, err
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(C.htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, nil, err
	}

	err = syscall.BindToDevice(fd, iface)
	if err != nil {
		syscall.Close(fd)
		return nil, nil, err
	}

	sniffer := &Sniffer{
		buffer:     make([]byte, 65536),
		fd:         fd,
		ready:      make(chan []asoc.Entry, 10),
		queriesMax: queriesMax,
	}
	return sniffer, sniffer.ready, nil
}

func (s *Sniffer) SetFQDNFilter(f FQDNFilter) {
	s.fqdnFilter = f
}

func (s *Sniffer) SetIPFilter(f IPFilter) {
	s.ipFilter = f
}

func (s *Sniffer) getDNS() []asoc.Entry {
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
		var IP net.IP
		if IP4layer := packet.Layer(layers.LayerTypeIPv4); IP4layer != nil {
			ip, _ := IP4layer.(*layers.IPv4)
			IP = ip.SrcIP
		} else if IP6layer := packet.Layer(layers.LayerTypeIPv6); IP6layer != nil {
			ip, _ := IP6layer.(*layers.IPv6)
			IP = ip.SrcIP
		}

		IP4layer := packet.Layer(layers.LayerTypeIPv4)
		if IP4layer == nil {
			continue
		}

		var entries []asoc.Entry
		t := time.Now()

		for i := range dns.Questions {
			if s.fqdnFilter != nil {
				if s.fqdnFilter(string(dns.Questions[i].Name)) {
					continue
				}
				if s.ipFilter(IP) {
					continue
				}
			}
			entries = append(entries, asoc.Entry{Time: t, IP: IP, QType: dns.Questions[i].Type.String(), FQDN: string(dns.Questions[i].Name)})
		}
		return entries
	}
}

func (s *Sniffer) Sniff() {
	var buff []asoc.Entry
	for {
		dns := s.getDNS()
		buff = append(buff, dns...)
		if len(buff) > s.queriesMax {
			s.ready <- buff
			buff = nil
		}
	}
}
