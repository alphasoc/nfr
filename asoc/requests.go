package asoc

import (
	"fmt"
	"syscall"
)

type Entry [4]string

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
	//todo discuss about platform and version (how to pass it)
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
