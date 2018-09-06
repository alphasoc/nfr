package alerts

import (
	"fmt"
	"net"
	"time"
)

func ExampleFormatterCEF_dns() {
	f := NewFormatterCEF()

	b, err := f.Format(&Event{
		Type:   "dns",
		Flags:  []string{"c2", "young_domain"},
		Groups: []Group{Group{Label: "boston"}},
		Threats: map[string]Threat{
			"c2_comm": Threat{
				Severity:    5,
				Description: "C2 communication",
			},
			"nevermind": Threat{
				Severity:    1,
				Description: "not important",
			},
		},
		Timestamp:  time.Unix(1536242944, 123e6),
		SrcIP:      net.IPv4(1, 2, 3, 4),
		Query:      "virus.com",
		RecordType: "A",
	})

	if err != nil {
		panic(err)
	}

	fmt.Print(string(b))

	// Output: CEF:0|AlphaSOC|NFR|0.0.0|c2_comm|C2 communication|10|app=dns start=Sep 06 2018 16:09:04.123 CEST src=1.2.3.4 cs1=c2,young_domain cs2=boston query=virus.com requestMethod=A
}

func ExampleFormatterCEF_ip() {
	f := NewFormatterCEF()

	b, err := f.Format(&Event{
		Type:   "ip",
		Flags:  []string{"c2", "young_domain"},
		Groups: []Group{Group{Label: "boston"}},
		Threats: map[string]Threat{
			"c2_comm": Threat{
				Severity:    5,
				Description: "C2 communication",
			},
			"nevermind": Threat{
				Severity:    1,
				Description: "not important",
			},
		},
		Timestamp: time.Unix(1536242944, 123e6),
		SrcIP:     net.IPv4(1, 2, 3, 4),
		SrcPort:   16830,
		DstIP:     net.IPv4(4, 3, 2, 1),
		DstPort:   443,
		Protocol:  "tcp",
		BytesIn:   744,
		BytesOut:  1376,
	})

	if err != nil {
		panic(err)
	}

	fmt.Print(string(b))

	// Output: CEF:0|AlphaSOC|NFR|0.0.0|c2_comm|C2 communication|10|app=ip start=Sep 06 2018 16:09:04.123 CEST src=1.2.3.4 cs1=c2,young_domain cs2=boston spt=16830 dst=4.3.2.1 dpt=443 proto=tcp in=744 out=1376
}
