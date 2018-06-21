package ja3

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/alphasoc/nfr/gopacket/ssl"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Convert converts raw packet to ja3 digest.
// It retruns empty string if packet is not convertable to ja3.
func Convert(raw gopacket.Packet) string {
	_, digest := convert(raw)
	return digest
}

func convert(raw gopacket.Packet) (string, string) {
	var transportLayer = raw.TransportLayer()

	tcp, ok := transportLayer.(gopacket.Layer).(*layers.TCP)
	if !ok {
		return "", ""
	}

	payload := tcp.LayerPayload()
	if len(payload) == 0 || uint8(payload[0]) != ssl.TLS_HANDSHAKE {
		return "", ""
	}

	// FIXME: panic if len(tcp.LayerPayload()) < 2; fix here or in alphasoc/nfr/gopacket/ssl
	record := ssl.GetTLSRecord(tcp.LayerPayload())
	if record == nil {
		return "", ""
	}

	if record.Type != ssl.TLS_HANDSHAKE || record.Length == 0 {
		return "", ""
	}

	clientHello := record.TLSClientHello()
	if clientHello == nil {
		return "", ""
	}

	var ja3 []string
	ja3 = append(ja3, strconv.FormatInt(int64(clientHello.Version), 10))

	seg, err := convertToJa3Segment(clientHello.CipherSuites, 2)
	if err != nil {
		return "", ""
	}
	ja3 = append(ja3, seg)

	exts, err := processExtensions(clientHello)
	if err != nil {
		return "", ""
	}

	ja3 = append(ja3, exts...)

	ja3Str := strings.Join(ja3, ",")
	ja3Hash := md5.Sum([]byte(ja3Str))
	return ja3Str, hex.EncodeToString(ja3Hash[:])
}

func convertToJa3Segment(buf []byte, elemWidth int) (string, error) {
	var vals []string
	if len(buf)%elemWidth != 0 {
		return "", errors.New("len(buf) not multiple")
	}

	for i := 0; i < len(buf); i += elemWidth {
		var element uint16
		if elemWidth == 1 {
			element = uint16(uint8(buf[i]))
		} else {
			element = uint16(buf[i])<<8 | uint16(buf[i+1])
		}
		if !ssl.TLSGreaseCiperSiutes[element] {
			vals = append(vals, strconv.FormatInt(int64(element), 10))
		}
	}
	return strings.Join(vals, "-"), nil
}

func processExtensions(clientHello *ssl.TLSClientHello) (exts []string, err error) {
	if len(clientHello.Extensions) == 0 {
		// Needed to preserve commas on the join
		return []string{"", "", ""}, nil
	}

	var (
		ellipticCurve            = ""
		ellipticCurvePointFormat = ""
	)

	for _, ext := range clientHello.Extensions {
		if !ssl.TLSGreaseCiperSiutes[ext.Type] {
			exts = append(exts, strconv.FormatInt(int64(ext.Type), 10))
		}
		if ext.Type == 0x0a {
			l := uint16(ext.Data[0])<<8 | uint16(ext.Data[1])
			ellipticCurve, err = convertToJa3Segment(ext.Data[2:l+2], 2)
			if err != nil {
				return nil, err
			}
		} else if ext.Type == 0x0b {
			l := uint8(ext.Data[0])
			ellipticCurvePointFormat, err = convertToJa3Segment(ext.Data[1:l+1], 1)
			if err != nil {
				return nil, err
			}
		}
	}

	return []string{strings.Join(exts, "-"), ellipticCurve, ellipticCurvePointFormat}, nil
}
