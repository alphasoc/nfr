// Package ssl parse TCP ssl data.
package ssl

import (
	"fmt"

	"github.com/bradleyfalzon/tlsx"
)

// SSL Message type
const (
	TLS_HANDSHAKE = 22
)

// TLSGreaseCiperSiutes table ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
var TLSGreaseCiperSiutes = map[int]bool{
	0x0a0a: true,
	0x1a1a: true,
	0x2a2a: true,
	0x3a3a: true,
	0x4a4a: true,
	0x5a5a: true,
	0x6a6a: true,
	0x7a7a: true,
	0x8a8a: true,
	0x9a9a: true,
	0xaaaa: true,
	0xbaba: true,
	0xcaca: true,
	0xdada: true,
	0xeaea: true,
	0xfafa: true,
}

type TLSRecord struct {
	Type    uint8
	Version uint16
	Length  uint16
}

func newTLSRecord(buf []byte) *TLSRecord {

	return &TLSRecord{}
}

// // TLSRecords
func TLSRecords(buf []byte) ([]*TLSRecord, error) {
	var records []*TLSRecord
	for i, n := 0, len(buf); i+5 <= n; {
		v = buf[i+1 : i+3]
		if _, ok := tlsx.VersionReg[v]; ok {
			return nil, fmt.Errorf("Bad TLS version in buf: %s", buf[i:i+5])
		}

		if record = newTLSRecord(buf[i:]); record != nil {
			records.append(record)
			i += len(40)
		} else {
			break
		}
	}
	return records, nil
}

// // TLSHandshake
// func TLSHandshake() {

// }

// // TLSClientHello
// func TLSClientHello() {

// }
