// Package tls parse TCP tls data.
package ssl

import (
	"crypto/tls"
)

const (
	VersionTLS13 = 0x304
)

// SSL Message type
const (
	TLS_HANDSHAKE    = 22
	TLS_CLIENT_HELLO = 1
)

const (
	TLS_CLIENT_HELLO_RANDOM_LEN = 32
)

// TLSGreaseCiperSiutes table ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
var TLSGreaseCiperSiutes = map[uint16]bool{
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

const TLSRecordHeaderLength = 5

type TLSRecord struct {
	Type    uint8
	Version uint16
	Length  uint16
	Data    []byte
}

type TLSExtension struct {
	Type uint16
	Data []byte
}

type TLSClientHello struct {
	Type               uint8
	Length             uint32
	Version            uint16
	Random             []byte
	SessionIDLen       uint8
	SessionID          []byte
	CipherSuitesLen    uint16
	CipherSuites       []byte
	NumCompressMethods uint8
	CompressMethods    []uint8
	ExtensionsLen      uint16
	Extensions         []TLSExtension
}

func newTLSRecord(buf []byte) *TLSRecord {
	if len(buf) < TLSRecordHeaderLength {
		return nil
	}

	var record = TLSRecord{
		Type:    uint8(buf[0]),
		Version: uint16(buf[1])<<8 | uint16(buf[2]),
		Length:  uint16(buf[3])<<8 | uint16(buf[4]),
	}

	if len(buf) < int(record.Length+TLSRecordHeaderLength) {
		return nil
	}

	record.Data = buf[TLSRecordHeaderLength : TLSRecordHeaderLength+record.Length]
	return &record
}

func GetTLSRecord(buf []byte) *TLSRecord {
	version := uint16(buf[1])<<8 | uint16(buf[2])
	if version < tls.VersionSSL30 || version > VersionTLS13 {
		return nil
	}

	return newTLSRecord(buf)
}

func (r *TLSRecord) TLSClientHello() *TLSClientHello {
	var (
		clientHello TLSClientHello
		buf         = r.Data
	)

	if len(buf) < 6+TLS_CLIENT_HELLO_RANDOM_LEN {
		return nil
	}
	if clientHello.Type = uint8(buf[0]); clientHello.Type != TLS_CLIENT_HELLO {
		return nil
	}

	clientHello.Length = uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
	clientHello.Version = uint16(buf[4])<<8 | uint16(buf[5])
	clientHello.Random = buf[6 : 6+TLS_CLIENT_HELLO_RANDOM_LEN]
	buf = buf[6+TLS_CLIENT_HELLO_RANDOM_LEN:]

	if len(buf) < 1 {
		return nil
	}
	clientHello.SessionIDLen = uint8(buf[0])
	buf = buf[1:]

	if len(buf) < int(clientHello.SessionIDLen) {
		return nil
	}
	clientHello.SessionID = buf[:clientHello.SessionIDLen]
	buf = buf[clientHello.SessionIDLen:]

	if len(buf) < 2 {
		return nil
	}

	clientHello.CipherSuitesLen = (uint16(buf[0])<<8 | uint16(buf[1])) / 2
	buf = buf[2:]

	if len(buf) < int(clientHello.CipherSuitesLen) {
		return nil
	}

	clientHello.CipherSuites = make([]byte, clientHello.CipherSuitesLen*2)
	for i := 0; i < int(clientHello.CipherSuitesLen*2); i++ {
		clientHello.CipherSuites[i] = buf[i]
	}
	buf = buf[clientHello.CipherSuitesLen*2:]

	if len(buf) < 1 {
		return nil
	}

	clientHello.NumCompressMethods = uint8(buf[0])
	if len(buf) < int(clientHello.NumCompressMethods) {
		return nil
	}
	buf = buf[1:]

	clientHello.CompressMethods = make([]uint8, clientHello.NumCompressMethods)
	for i := 0; i < int(clientHello.NumCompressMethods); i++ {
		clientHello.CompressMethods[i] = uint8(buf[i])
	}
	buf = buf[clientHello.NumCompressMethods:]

	if len(buf) > 6 {
		clientHello.Extensions = make([]TLSExtension, 0)
		clientHello.ExtensionsLen = uint16(buf[0])<<8 | uint16(buf[1])
		buf = buf[2:]

		for len(buf) > 0 {
			extType := uint16(buf[0])<<8 | uint16(buf[1])
			buf = buf[2:]
			l := uint16(buf[0])<<8 | uint16(buf[1])
			buf = buf[2:]

			extData := buf[:l]
			clientHello.Extensions = append(clientHello.Extensions, TLSExtension{Type: extType, Data: extData})
			buf = buf[l:]
		}
	}

	return &clientHello
}
