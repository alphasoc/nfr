package sniffer

import (
	"fmt"

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
	EnableDNSAnalitics bool
	Protocols          []string
	Port               int

	EnableIPAnalitics bool
}

// NewLivePcapSniffer creates sniffer that capture packets from interface.
func NewLivePcapSniffer(iface string, cfg *Config) (*PcapSniffer, error) {
	handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
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
	filter, err := sprintBPFFilter(cfg)
	if err != nil {
		handle.Close()
		return nil, err
	}

	if err := handle.SetBPFFilter(filter); err != nil {
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

// print pcap format filter based on given config
func sprintBPFFilter(cfg *Config) (string, error) {
	expr := ""

	// set expresion only when dns is turn on and ip is turn off.
	// in other cases just filter tcp and udp traffic.
	if cfg.EnableDNSAnalitics && !cfg.EnableIPAnalitics {
		if len(cfg.Protocols) > 2 {
			return "", fmt.Errorf("too many protocols in list")
		}

		for _, proto := range cfg.Protocols {
			if proto != "udp" && proto != "tcp" {
				return "", fmt.Errorf("invalid protocol %q name", proto)
			}
		}

		if cfg.Port <= 0 || cfg.Port > 65355 {
			return "", fmt.Errorf("invalid %d port number", cfg.Port)
		}

		switch len(cfg.Protocols) {
		case 1:
			expr = fmt.Sprintf("(%s dst port %d)", cfg.Protocols[0], cfg.Port)
		default:
			expr = fmt.Sprintf("(tcp or udp dst port %d)", cfg.Port)
		}
	} else {
		expr = "tcp or udp"
	}

	return expr, nil
}
