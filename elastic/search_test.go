package elastic

import (
	"fmt"
	"testing"
)

func ipProtoParse(val string) string {
	src := fmt.Sprintf(
		"{\"_source\":{\"device_version\":\"v7.0.1\",\"device_product\":\"Foogate\",\"FTNTFGTmastersrcmac\":\"00:00:00:00:00:00\",\"proto\":%v,\"FTNTFGTpoluuid\":\"00000000-0000-0000-0000-000000000000\"}}",
		val)
	h := Hit{
		ID:     "eFVpenwBwORpcXQ7osoi",
		Source: []byte(src),
	}
	return h.sourceProtocol([]string{"_source", "proto"})
}

func TestIPProtoParsing(t *testing.T) {
	valMap := make(map[string]string)
	valMap["\"6\""] = "tcp"
	valMap["6"] = "tcp"
	valMap["\"253\""] = "253"
	valMap["253"] = "253"
	valMap["not_a_json_string"] = ""
	valMap["\"udp\""] = "udp"
	valMap["\"foo\""] = "foo"
	valMap["256"] = ""
	valMap["0"] = ""
	valMap["-1"] = ""

	for k, v := range valMap {
		got := ipProtoParse(k)
		want := v
		if got != want {
			t.Errorf("from %q got %q, wanted %q", k, got, want)
		}
	}
}
