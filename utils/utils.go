package utils

import (
	"net"
	"os"
	"time"

	"github.com/alphasoc/namescore/client"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DecodePackets into api Queries request.
// Packtes that has diffrent header then DNS are droped.
func DecodePackets(packets []gopacket.Packet) *client.QueriesRequest {
	qr := client.QueriesRequest{Data: make([][4]string, 0, len(packets))}

	for i := range packets {
		ldns, ok := packets[i].ApplicationLayer().(gopacket.Layer).(*layers.DNS)
		if !ok || ldns.QR {
			continue
		}

		timestamp := time.Now()
		if md := packets[i].Metadata(); md != nil {
			timestamp = md.Timestamp
		}

		var srcIP net.IP
		if lipv4, ok := packets[i].TransportLayer().(gopacket.Layer).(*layers.IPv4); ok {
			srcIP = lipv4.SrcIP
		} else if lipv6, ok := packets[i].TransportLayer().(gopacket.Layer).(*layers.IPv6); ok {
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

// func ReadPcapFile(file string) ([]gopacket.Packet, error) {
// 	f, err := os.Open(file)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer f.Close()
// 
// 	r, err := pcapgo.NewReader(f)
// 	if err != nil {
// 		return nil, err
// 	}
// 
// 	var packets []gopacket.Packet
// 	for {
// 		data, _, err := r.ReadPacketData()
// 		if err == io.EOF {
// 			break
// 		}
// 		if err != nil {
// 			return nil, err
// 		}
// 
// 		packet := gopacket.NewPacket(data, layers.LinkTypeRaw, gopacket.DecodeOptions{
// 			Lazy:               true,
// 			NoCopy:             true,
// 			SkipDecodeRecovery: true,
// 		})
// 
// 		if l, ok := packet.ApplicationLayer().(gopacket.Layer).(*layers.DNS); !ok || l.QR {
// 			// only dns query packets can be procceed by api
// 			continue
// 		}
// 
// 		packets = append(packets, packet)
// 	}
// 	return packets, nil
// }

func SendPcapFile(c *client.Client, cfg* config.Config, file string) error {
	s, err := sniffer.NewDNSSnifferFromFile(file, cfg.Network.Protocols, cfg.Network.Port)
	if err != nil {
		return err
	}

	buf := queries.NewBuffer(queries.Size(cfg.Queries.Size))
	for packet := range s.Source.Packets() {
		buf.Write(packet)
		if buf.Len() < cfg.Queries.Size {
			continue
		}
		packets := buf.Read()
		if _, err := c.Queries(DecodePackets(packets)); err != nil {
			return err
		}
		buf.Clear()
	}

	return os.Rename(file, file+"."+time.Now().Format(time.RFC3339))
}
