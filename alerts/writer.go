package alerts

import (
	"bytes"
	"encoding/json"
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
	Format(*Event) ([]byte, error)
}

type FormatterJSON struct {
}

func (FormatterJSON) Format(event *Event) ([]byte, error) {
	return json.Marshal(event)
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

func (f *FormatterCEF) Format(event *Event) ([]byte, error) {
	if len(event.Threats) == 0 {
		return nil, nil
	}

	threatID, threat := event.topThreat()

	var buf bytes.Buffer
	l := ceflog.New(&buf, f.vendor, f.product, f.version)

	// CEF log extensions
	ext := ceflog.Extension{
		{"app", event.EventType},
		{"start", event.Timestamp.Format(cefTimeFormat)},
		{"src", event.SrcIP.String()},
		{"cs1", strings.Join(event.Flags, ",")},
	}

	if len(event.Groups) > 0 {
		groups := make([]string, len(event.Groups))
		for n := range event.Groups {
			groups[n] = event.Groups[n].Label
		}
		ext = append(ext, ceflog.Pair{"cs2", strings.Join(groups, ",")})
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

	// write event to buffer
	l.LogEvent(
		threatID,
		threat.Description,
		ceflog.Severity(threat.Severity*2), // 0-10 scale
		ext)

	return buf.Bytes(), nil
}
