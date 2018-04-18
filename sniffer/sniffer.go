package sniffer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Sniffer is an interface for iterate over captured packets.
type Sniffer interface {
	Packets() chan gopacket.Packet // channel with captured packets
}

// PcapSniffer sniffs dns packets.
type PcapSniffer struct {
	handle *pcap.Handle
	source *gopacket.PacketSource
}

// Config options for sniffer.
type Config struct {
	BPFilter string
}

// NewLivePcapSniffer creates sniffer that capture packets from interface.
func NewLivePcapSniffer(iface string, cfg *Config) (*PcapSniffer, error) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return newsniffer(handle, cfg)
}

// NewOfflinePcapSniffer creates sniffer that capture packets from pcap file.
func NewOfflinePcapSniffer(file string, cfg *Config) (*PcapSniffer, error) {
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		return nil, err
	}
	return newsniffer(handle, cfg)
}

// newsniffer creates new sniffer and sets pcap filter for it.
func newsniffer(handle *pcap.Handle, cfg *Config) (*PcapSniffer, error) {
	if err := handle.SetBPFFilter(cfg.BPFilter); err != nil {
		handle.Close()
		return nil, err
	}

	return &PcapSniffer{
		source: gopacket.NewPacketSource(handle, handle.LinkType()),
		handle: handle,
	}, nil
}

// Packets returns a channel of captured packets, allowing easy iterating over them.
func (s *PcapSniffer) Packets() chan gopacket.Packet {
	return s.source.Packets()
}

// Close closes underlying handle and stops sniffer.
func (s *PcapSniffer) Close() {
	s.handle.Close()
}
