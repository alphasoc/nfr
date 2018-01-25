package utils

import "net"

// IsSpecialIP returns true if given ip belongs
// to network address from RFC 3330 and RFC 5166.
func IsSpecialIP(ip net.IP) bool {
	for _, net := range SpecialIPv4Addresses {
		if net.Contains(ip) {
			return true
		}
	}
	for _, net := range SpecialIPv6Addresses {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

// Special-Use IPv4 and IPv6 Addresses
var (
	// Special-Use IPv4 Addresses RFC 3330 (https://tools.ietf.org/html/rfc3330)
	SpecialIPv4Addresses = []*net.IPNet{
		{
			// "This" Network
			IP:   net.IPv4(0, 0, 0, 0),
			Mask: net.CIDRMask(8, 32),
		},
		{
			// Private-Use Networks
			IP:   net.IPv4(10, 0, 0, 0),
			Mask: net.CIDRMask(8, 32),
		},
		{
			// Public-Data Networks
			IP:   net.IPv4(14, 0, 0, 0),
			Mask: net.CIDRMask(8, 32),
		},
		{
			// Cable Television Networks
			IP:   net.IPv4(24, 0, 0, 0),
			Mask: net.CIDRMask(8, 32),
		},
		{
			// Reserved but subject to allocation
			IP:   net.IPv4(39, 0, 0, 0),
			Mask: net.CIDRMask(8, 32),
		},
		{
			// Loopback
			IP:   net.IPv4(127, 0, 0, 0),
			Mask: net.CIDRMask(8, 32),
		},
		{
			// Reserved but subject to allocation
			IP:   net.IPv4(128, 0, 0, 0),
			Mask: net.CIDRMask(16, 32),
		},
		{
			// Link Local
			IP:   net.IPv4(169, 254, 0, 0),
			Mask: net.CIDRMask(16, 32),
		},
		{
			// Private-Use Networks
			IP:   net.IPv4(172, 16, 0, 0),
			Mask: net.CIDRMask(12, 32),
		},
		{
			// Reserved but subject to allocation
			IP:   net.IPv4(191, 255, 0, 0),
			Mask: net.CIDRMask(16, 32),
		},
		{
			// Reserved but subject to allocation
			IP:   net.IPv4(192, 0, 0, 0),
			Mask: net.CIDRMask(24, 32),
		},
		{
			// Test-Net
			IP:   net.IPv4(192, 0, 2, 0),
			Mask: net.CIDRMask(24, 32),
		},
		{
			// 6to4 Relay Anycast
			IP:   net.IPv4(192, 88, 99, 0),
			Mask: net.CIDRMask(24, 32),
		},
		{
			// Private-Use Networks
			IP:   net.IPv4(192, 168, 0, 0),
			Mask: net.CIDRMask(16, 32),
		},
		{
			// Network Interconnect Device Benchmark Testing
			IP:   net.IPv4(198, 18, 0, 0),
			Mask: net.CIDRMask(15, 32),
		},
		{
			// Reserved but subject to allocation
			IP:   net.IPv4(223, 255, 255, 0),
			Mask: net.CIDRMask(24, 32),
		},
		{
			// Multicast
			IP:   net.IPv4(224, 0, 0, 0),
			Mask: net.CIDRMask(4, 32),
		},
		{
			// Reserved for Future Use
			IP:   net.IPv4(240, 0, 0, 0),
			Mask: net.CIDRMask(4, 32),
		},
	}

	// Special-Use IPv6 Addresses RFC (https://tools.ietf.org/html/rfc5166)
	SpecialIPv6Addresses = []*net.IPNet{
		{
			// loopback address
			IP:   net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
			Mask: net.CIDRMask(128, 128),
		},
		{
			// Link-Scoped Unicast addresses
			IP:   net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Mask: net.CIDRMask(10, 128),
		},
		{
			// Unique-Local addresses
			IP:   net.IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Mask: net.CIDRMask(7, 128),
		},
		{
			// Documentation addresses
			IP: net.IP{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

			Mask: net.CIDRMask(32, 128),
		},
		{
			// 6to4 addresses
			IP:   net.IP{0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Mask: net.CIDRMask(16, 128),
		},
		{
			// Teredo addresses
			IP:   net.IP{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Mask: net.CIDRMask(32, 128),
		},
		{
			// 6bone addresses
			IP:   net.IP{0x5f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Mask: net.CIDRMask(8, 128),
		},
		{
			// 6bone addresses
			IP:   net.IP{0x3f, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Mask: net.CIDRMask(16, 128),
		},
		{
			// Overlay Routable Cryptographic Hash IDentifiers (ORCHID) addresses
			IP:   net.IP{0x20, 0x01, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Mask: net.CIDRMask(28, 128),
		},
		{
			// Multicast addresses
			IP:   net.IP{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Mask: net.CIDRMask(8, 128),
		},
	}
)
