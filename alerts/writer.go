package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/alphasoc/nfr/version"
	"github.com/xoebus/ceflog"
	"strconv"
	"strings"
)

// Writer interface for log api alerts response.
type Writer interface {
	Write(*Event) error
}

type Formatter interface {
	Format(*Event) ([][]byte, error)
}

type FormatterJSON struct {
}

func (FormatterJSON) Format(event *Event) ([][]byte, error) {
	b, err := json.Marshal(event)
	return [][]byte{b}, err
}

type FormatterCEF struct {
	vendor, product, version string
}

func NewFormatterCEF() *FormatterCEF {
	return &FormatterCEF{
		vendor:  DefaultLogVendor,
		product: DefaultLogProduct,
		version: DefaultLogVersion,
	}
}

var (
	DefaultLogVendor  = "AlphaSOC"
	DefaultLogProduct = "NFR"
	DefaultLogVersion = version.Version

	cefTimeFormat = "Jan 02 2006 15:04:05.000 MST"
)

func cefCustomString(id int, label, value string) []ceflog.Pair {
	key := fmt.Sprintf("cs%d", id)
	return []ceflog.Pair{
		{key, value},
		{key + "Label", label},
	}
}

func (f *FormatterCEF) Format(event *Event) ([][]byte, error) {
	var res [][]byte

	// CEF log extensions
	ext := ceflog.Extension{
		{"app", event.EventType},
		{"rt", event.Timestamp.Format(cefTimeFormat)},
		{"src", event.SrcIP.String()},
	}

	if v := strings.Join(event.Flags, ","); v != "" {
		ext = append(ext, cefCustomString(1, "flags", v)...)
	}
	if len(event.Groups) > 0 {
		groups := make([]string, len(event.Groups))
		for n := range event.Groups {
			groups[n] = event.Groups[n].Label
		}
		ext = append(ext, cefCustomString(2, "groups", strings.Join(groups, ","))...)
	}

	switch event.EventType {
	case "dns":
		ext = append(ext, ceflog.Extension{
			{"query", event.Query},
			{"requestMethod", event.RecordType},
		}...)
	case "ip":
		ext = append(ext, ceflog.Extension{
			{"spt", strconv.Itoa(event.SrcPort)},
			{"dst", event.DstIP.String()},
			{"dpt", strconv.Itoa(event.DstPort)},
			{"proto", event.Protocol},
			{"in", strconv.Itoa(event.BytesIn)},
			{"out", strconv.Itoa(event.BytesOut)},
		}...)
	}

	// Format each threat as a separate event
	for threatID, threat := range event.Threats {
		var buf bytes.Buffer
		l := ceflog.New(&buf, f.vendor, f.product, f.version)

		// write event to buffer
		l.LogEvent(
			threatID,
			threat.Description,
			ceflog.Severity(threat.Severity*2), // 0-10 scale
			ext)

		res = append(res, bytes.TrimRight(buf.Bytes(), "\n"))
	}

	return res, nil
}
