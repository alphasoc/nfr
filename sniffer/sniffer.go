// Package sniffer provides functions for sniffing dns packets.
package sniffer

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// DNSSniffer is performing DNS request sniffing on local NIC.
type DNSSniffer struct {
	handle *pcap.Handle
	source *gopacket.PacketSource
}

// NewLive is preparing sniffer to capture packets from interface.
func NewLive(iface string, protocols []string, port int) (*DNSSniffer, error) {
	handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return newDNSSniffer(handle, protocols, port)
}

// NewOffline is preparing sniffer to capture packets from file.
func NewOffline(file string, protocols []string, port int) (*DNSSniffer, error) {
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		return nil, err
	}
	return newDNSSniffer(handle, protocols, port)

}

func newDNSSniffer(handle *pcap.Handle, protocols []string, port int) (*Sniffer, error) {
	if err := handle.SetBPFFilter(printBPFFilter(protocols, port)); err != nil {
		handle.Close()
		return nil, err
	}

	return &Sniffer{
		source: gopacket.NewPacketSource(handle, handle.LinkType()),
		handle: handle,
	}, nil
}

func (s *Sniffer) Packets() chan gopacket.Packet {
	return s.source.Packets()
}

// Close stops Sniffer.
func (s *Sniffer) Close() {
	s.handle.Close()
}

func printBPFFilter(protocols []string, port int) string {
	switch len(protocols) {
	case 1:
		return fmt.Sprintf("%s dst port %d dns && (dns.flags.response == 0) && ! dns.response_in", protocols[0], port)
	default:
		return fmt.Sprintf("(udp || tcp) dst port %d dns && (dns.flags.response == 0) && ! dns.response_in", port)
	}
}
