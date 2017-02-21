package asoc

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// Entry contains information about single DNS request.
type Entry struct {
	Time  time.Time
	IP    net.IP
	QType string
	FQDN  string
}

// QueriesReq contains slice of queries which are sent to
// AlphaSOC for analysis.
// It is used by "/v1/queries" API call.
type QueriesReq struct {
	Data []Entry `json:"data"`
}

type keyRequestReq struct {
	Platform struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"platform"`
	Uname string `json:"uname"`
	Token string `json:"token"`
}

// RegisterReq contains information needed to register API key.
// It is used by "/v1/account/register" API call.
type RegisterReq struct {
	Details struct {
		Name         string    `json:"name"`
		Organization string    `json:"organization"`
		Email        string    `json:"email"`
		Phone        string    `json:"phone"`
		Address      [3]string `json:"address"`
	} `json:"details"`
}

func createKeyRequest() keyRequestReq {
	req := keyRequestReq{Uname: uname()}
	req.Platform.Name = "namescore"
	req.Platform.Version = "0.1"
	return req
}

func int8tostr(buffer [65]int8) string {
	b := make([]byte, 65)
	for i, v := range buffer {
		b[i] = byte(v)
	}
	return string(b)
}

func uname() string {
	u := syscall.Utsname{}
	if syscall.Uname(&u) != nil {
		return ""
	}
	return fmt.Sprintf("%s | %s | %s | %s | %s",
		int8tostr(u.Sysname),
		int8tostr(u.Nodename),
		int8tostr(u.Release),
		int8tostr(u.Version),
		int8tostr(u.Machine))
}

// MarshalJSON converts Entry structure to JSON
// format.
func (e *Entry) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString("[")
	str := fmt.Sprintf(`"%s","%s","%s","%s"]`, e.Time.Format(time.RFC3339), e.IP.String(), e.QType, e.FQDN)

	if _, err := buffer.WriteString(str); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// UnmarshalJSON converts JSON data to Entry
func (e *Entry) UnmarshalJSON(data []byte) error {
	if data == nil {
		return fmt.Errorf("Entry: data is empty")
	}

	str := string(data)
	str = strings.TrimPrefix(str, "[")
	str = strings.TrimSuffix(str, "]")
	str = strings.Replace(str, ",", " ", -1)
	str = strings.Replace(str, "\"", "", -1)

	var tim string
	var ip string
	var qtype string
	var fqdn string
	if _, err := fmt.Sscanf(str, "%s %s %s %s", &tim, &ip, &qtype, &fqdn); err != nil {
		return err
	}

	e.FQDN = fqdn
	e.IP = net.ParseIP(ip)
	e.QType = qtype

	t, err := time.Parse(time.RFC3339, tim)
	if err != nil {
		return err
	}
	e.Time = t
	return nil
}
