package alerts

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/alphasoc/nfr/client"
)

func bytesToSortedStrings(bs [][]byte) []string {
	s := make([]string, len(bs))
	for n := range bs {
		s[n] = string(bs[n])
	}
	sort.Strings(s)
	return s
}

func ExampleFormatterCEF_dns() {
	f := NewFormatterCEF()

	bs, err := f.Format(&Event{
		Type:      "alert",
		EventType: "dns",
		Flags:     []string{"c2", "young_domain"},
		Groups:    []Group{Group{Label: "boston"}},
		Threats: map[string]Threat{
			"c2_comm": Threat{
				Severity:    5,
				Description: "C2 communication",
			},
			"interesting": Threat{
				Severity:    2,
				Description: "Interesting event",
			},
		},
		EventUnified: client.EventUnified{
			Timestamp: time.Unix(1536242944, 123e6).UTC(),
			SrcIP:     net.IPv4(1, 2, 3, 4),
			Query:     "virus.com",
			QueryType: "A",
		},
	})

	if err != nil {
		panic(err)
	}

	fmt.Print(strings.Join(bytesToSortedStrings(bs), "\n"))

	// Output:
	// CEF:0|AlphaSOC|NFR|0.0.0|c2_comm|C2 communication|10|app=dns rt=Sep 06 2018 14:09:04.123 UTC src=1.2.3.4 cs1=c2,young_domain cs1Label=flags cs2=boston cs2Label=groups query=virus.com requestMethod=A
	// CEF:0|AlphaSOC|NFR|0.0.0|interesting|Interesting event|4|app=dns rt=Sep 06 2018 14:09:04.123 UTC src=1.2.3.4 cs1=c2,young_domain cs1Label=flags cs2=boston cs2Label=groups query=virus.com requestMethod=A
}

func ExampleFormatterCEF_ip() {
	f := NewFormatterCEF()

	bs, err := f.Format(&Event{
		Type:      "alert",
		EventType: "ip",
		Flags:     []string{"c2", "young_domain"},
		Groups:    []Group{Group{Label: "boston"}},
		Threats: map[string]Threat{
			"c2_comm": Threat{
				Severity:    5,
				Description: "C2 communication",
			},
			"interesting": Threat{
				Severity:    2,
				Description: "Interesting event",
			},
		},
		EventUnified: client.EventUnified{
			Timestamp: time.Unix(1536242944, 123e6).UTC(),
			SrcIP:     net.IPv4(1, 2, 3, 4),
			SrcPort:   16830,
			DestIP:    net.IPv4(4, 3, 2, 1),
			DestPort:  443,
			Proto:     "tcp",
			BytesIn:   744,
			BytesOut:  1376,
		},
	})

	if err != nil {
		panic(err)
	}

	fmt.Print(strings.Join(bytesToSortedStrings(bs), "\n"))

	// Output:
	// CEF:0|AlphaSOC|NFR|0.0.0|c2_comm|C2 communication|10|app=ip rt=Sep 06 2018 14:09:04.123 UTC src=1.2.3.4 cs1=c2,young_domain cs1Label=flags cs2=boston cs2Label=groups spt=16830 dst=4.3.2.1 dpt=443 proto=tcp in=744 out=1376
	// CEF:0|AlphaSOC|NFR|0.0.0|interesting|Interesting event|4|app=ip rt=Sep 06 2018 14:09:04.123 UTC src=1.2.3.4 cs1=c2,young_domain cs1Label=flags cs2=boston cs2Label=groups spt=16830 dst=4.3.2.1 dpt=443 proto=tcp in=744 out=1376
}
