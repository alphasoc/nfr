package DNSContainer

import "testing"

func BenchmarkAdd(b *testing.B) {
	c := Create(1000)
	e := &Entry{FQDN: "test.com", QType: "A", SourceIP: "0.0.0.0", Time: "time"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Add(e)
	}
}
