package AlphaSocAPI

// import (
// 	"bytes"
// 	"encoding/json"
// 	"fmt"
// 	"io/ioutil"
// 	"net/http"
// 	"syscall"
// )

// type keyRequestReq struct {
// 	Platform keyRequestPlatform `json:"platform"`
// 	Uname    string             `json:"uname"`
// 	Token    string             `json:"token"`
// }

// type keyRequestPlatform struct {
// 	Name    string `json:"name"`
// 	Version string `json:"version"`
// }

// func dupa(s [65]int8) string {
// 	var c []byte
// 	for _, v := range s {
// 		if v == 0 {
// 			break
// 		}
// 		c = append(c, byte(v))
// 	}
// 	return string(c)
// }

// //todo more elegant []int8 handling
// func getUname() string {
// 	uname := syscall.Utsname{}
// 	if syscall.Uname(&uname) != nil {
// 		return ""
// 	}

// 	r := fmt.Sprintf("%s | %s | %s | %s | %s", dupa(uname.Sysname), dupa(uname.Nodename), dupa(uname.Release), dupa(uname.Version), dupa(uname.Machine))

// 	return r

// }

// func createKeyRequest() *keyRequestReq {
// 	//todo discuss about platform and version (how to pass it)
// 	k := &keyRequestReq{Platform: keyRequestPlatform{"namescore", "0.1"}, Uname: getUname()}
// 	return k
// }

// func (c *Client) Request() (string, error) {
// 	req := createKeyRequest()
// 	reqJson, errj := json.Marshal(*req)

// 	if errj != nil {
// 		return "", fmt.Errorf("Request(), failed json body err=%q", errj)
// 	}

// 	ca := http.Client{}

// 	a, b := ca.Post("http://localhost:8080/v1/key/request", "application/json", bytes.NewReader(reqJson))

// 	if b != nil {
// 		fmt.Println("err ", b)
// 		return "", nil
// 	}
// 	fmt.Println(a)

// 	n, _ := ioutil.ReadAll(a.Body)
// 	fmt.Printf("kubaa %s\n", n)

// 	// p := KeyRequest{platform{"Splunk", "6.6"}, "linux", ""}

// 	// ma, e := json.Marshal(p)
// 	// if e != nil {
// 	// 	fmt.Println(e)
// 	// } else {
// 	// 	fmt.Println(ma)
// 	// 	fmt.Println(p)
// 	// }

// 	return "", nil
// }
