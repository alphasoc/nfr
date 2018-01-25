package utils

import (
	"net"
	"testing"
)

func BenchmarkIsSpecialIP(b *testing.B) {
	ip := net.IPv4(1, 2, 3, 4)
	for n := 0; n < b.N; n++ {
		IsSpecialIP(ip)
	}
}
