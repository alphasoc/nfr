package utils

import (
	"io"
	"net"
	"os"
	"time"

	"github.com/alphasoc/namescore/client"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// DecodePackets into api Queries request.
// Packtes that has diffrent header then DNS are droped.
func DecodePackets(packets []gopacket.Packet) *client.QueriesRequest {
	qr := client.QueriesRequest{Data: make([][4]string, 0, len(packets))}

	for i := range packets {
		ldns, ok := packets[i].Layer(layers.LayerTypeDNS).(*layers.DNS)
		if !ok {
			continue
		}

		timestamp := time.Now()
		if md := packets[i].Metadata(); md != nil {
			timestamp = md.Timestamp
		}

		var srcIP net.IP
		if lipv4, ok := packets[i].Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
			srcIP = lipv4.SrcIP
		} else if lipv6, ok := packets[i].Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
			srcIP = lipv6.SrcIP
		}

		for _, q := range ldns.Questions {
			qr.Data = append(qr.Data, [4]string{
				timestamp.Format(time.RFC3339),
				srcIP.String(),
				q.Type.String(),
				string(q.Name),
			})
		}
	}
	return nil
}

func ReadPcapFile(file string) ([]gopacket.Packet, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, err
	}

	var packets []gopacket.Packet
	for {
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		packet := gopacket.NewPacket(data, layers.LinkTypeRaw, gopacket.DecodeOptions{
			Lazy:               true,
			NoCopy:             true,
			SkipDecodeRecovery: true,
		})

		if packet.Layer(layers.LayerTypeDNS) == nil {
			// only DNS packets can be procced by api
			continue
		}

		packets = append(packets, packet)
	}
	return packets, nil
}

func SendPcapFile(c *client.Client, file string) (*client.QueriesResponse, error) {
	packets, err := ReadPcapFile(file)
	if err != nil {
		return nil, err
	}

	resp, err := c.Queries(DecodePackets(packets))
	if err != nil {
		return nil, err
	}

	return resp, os.Rename(file, file+"."+time.Now().Format(time.RFC3339))
}
