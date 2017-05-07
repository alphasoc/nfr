// Package dns provides functions for DNS packet sniffing.
package sniffer

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Sniffer is performing DNS request sniffing on local NIC.
type Sniffer struct {
	handle     *pcap.Handle
	Source     *gopacket.PacketSource
}

// NewDNSSniffer is preparing sniffer to capture packets.
// After this function finish, packets can be retrieved from packetSource
func NewDNSSnifferFromInterface(iface string, protocols []string, port int) (*Sniffer, error) {
	handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return newDNSSniffer(handle, protocols, port)
}

func NewDNSSnifferFromFile(file string, protocols []string, port int) (*Sniffer, error) {
	handle, err := pcap.OpenOffline(file, 1600, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return newDNSSniffer(handle, protocols, port)

}

func newDNSSniffer(handle pcap.Handle, protocols []string, port int) (*Sniffer, error) {
	if err := handle.SetBPFFilter(printBPFFilter(protocosl, port)); err != nil {
		handle.Close()
		return nil, err
	}

	return &Sniffer{
		Source: gopacket.NewPacketSource(handle, handle.LinkType()),
		handle: handle,
	}, nil
}

// Close stops Sniffer.
func (s *Sniffer) Close() {
	s.handle.Close()
}

func printBPFFilter(protocols []string, port int) string {
	case len(protocols) {
	case 1:
		return fmt.Sprintf("%s dst port %d dns && (dns.flags.response == 0) && ! dns.response_in", protocosl[0], port)
	default:
		return fmt.Sprintf("(udp || tcp) dst port %d dns && (dns.flags.response == 0) && ! dns.response_in",  port)
	}
}
