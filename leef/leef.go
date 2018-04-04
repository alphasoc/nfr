package leef

import (
	"bytes"
	"errors"
	"net"
	"strconv"
)

const (
	leefVersion     = "2.0"
	headerSeparator = "|"
	eventSeparator  = "\t"
)

// An Event LEEF.
type Event struct {
	buf         *bytes.Buffer
	isHeaderSet bool
}

// NewEvent creates new LEEF event.
func NewEvent() *Event {
	return &Event{buf: &bytes.Buffer{}}
}

// SetHeader sets events header.
func (e *Event) SetHeader(vendor, product, version, event string) error {
	if e.isHeaderSet {
		return errors.New("LEEF header already set")
	}

	e.buf.WriteString("LEEF:" + leefVersion)
	e.buf.WriteString(headerSeparator)
	e.buf.WriteString(vendor)
	e.buf.WriteString(headerSeparator)
	e.buf.WriteString(product)
	e.buf.WriteString(headerSeparator)
	e.buf.WriteString(version)
	e.buf.WriteString(headerSeparator)
	e.buf.WriteString(event)
	e.buf.WriteString(headerSeparator)
	e.isHeaderSet = true
	return nil
}

// SetAttr sets event attribute.
func (e *Event) SetAttr(key, value string) error {
	if !e.isHeaderSet {
		return errors.New("LEEF event attribute cannot be set before header")
	}

	e.buf.WriteString(key + "=")
	e.buf.WriteString(value)
	e.buf.WriteString(eventSeparator)
	return nil
}

// SetCatAttr sets cat event attribute.
func (e *Event) SetCatAttr(value string) error { return e.SetAttr("cat", value) }

// SetDevTimeAttr sets devTime event attribute.
func (e *Event) SetDevTimeAttr(value string) error { return e.SetAttr("devTime", value) }

// SetDevTimeFormatAttr sets devTimeFormat event attribute.
func (e *Event) SetDevTimeFormatAttr(value string) error { return e.SetAttr("devTimeFormat", value) }

// SetProtoAttr sets proto event attribute.
func (e *Event) SetProtoAttr(value string) error { return e.SetAttr("proto", value) }

// SetSevAttr sets sev event attribute.
func (e *Event) SetSevAttr(value int) error {
	return e.SetAttr("sev", strconv.FormatInt(int64(value), 10))
}

// SetSrcAttr sets src event attribute.
func (e *Event) SetSrcAttr(value net.IP) error { return e.SetAttr("src", value.String()) }

// SetDstAttr sets dst event attribute.
func (e *Event) SetDstAttr(value net.IP) error { return e.SetAttr("dst", value.String()) }

// SetSrcPortAttr sets srcPort event attribute.
func (e *Event) SetSrcPortAttr(value int) error {
	return e.SetAttr("srcPort", strconv.FormatInt(int64(value), 10))
}

// SetDstPortAttr sets dstPort event attribute.
func (e *Event) SetDstPortAttr(value int) error {
	return e.SetAttr("dstPort", strconv.FormatInt(int64(value), 10))
}

// SetSrcPreNATAttr sets srcPreNAT event attribute.
func (e *Event) SetSrcPreNATAttr(value net.IP) error { return e.SetAttr("srcPreNAT", value.String()) }

// SetDstPreNATAttr sets dstPreNAT event attribute.
func (e *Event) SetDstPreNATAttr(value net.IP) error { return e.SetAttr("dstPreNAT", value.String()) }

// SetSrcPostNATAttr sets srcPostNAT event attribute.
func (e *Event) SetSrcPostNATAttr(value net.IP) error { return e.SetAttr("srcPostNAT", value.String()) }

// SetDstPostNATAttr sets dstPostNAT event attribute.
func (e *Event) SetDstPostNATAttr(value net.IP) error { return e.SetAttr("dstPostNAT", value.String()) }

// SetUserNameAttr sets userName event attribute.
func (e *Event) SetUserNameAttr(value string) error { return e.SetAttr("userName", value) }

// SetSrcMACAttr sets srcMAC event attribute.
func (e *Event) SetSrcMACAttr(value net.HardwareAddr) error {
	return e.SetAttr("srcMAC", value.String())
}

// SetDstMACAttr sets dstMAC event attribute.
func (e *Event) SetDstMACAttr(value net.HardwareAddr) error {
	return e.SetAttr("dstMAC", value.String())
}

// SetSrcPreNATPortAttr sets srcPreNATPort event attribute.
func (e *Event) SetSrcPreNATPortAttr(value int) error {
	return e.SetAttr("srcPreNATPort", strconv.FormatInt(int64(value), 10))
}

// SetDstPreNATPortAttr sets dstPreNATPort event attribute.
func (e *Event) SetDstPreNATPortAttr(value int) error {
	return e.SetAttr("dstPreNATPort", strconv.FormatInt(int64(value), 10))
}

// SetSrcPostNATPortAttr sets srcPostNATPort event attribute.
func (e *Event) SetSrcPostNATPortAttr(value int) error {
	return e.SetAttr("srcPostNATPort", strconv.FormatInt(int64(value), 10))
}

// SetDstPostNATPortAttr sets dstPostNATPort event attribute.
func (e *Event) SetDstPostNATPortAttr(value int) error {
	return e.SetAttr("dstPostNATPort", strconv.FormatInt(int64(value), 10))
}

// SetIdentSrcAttr sets identSrc event attribute.
func (e *Event) SetIdentSrcAttr(value net.IP) error { return e.SetAttr("identSrc", value.String()) }

// SetIdentHostNameAttr sets identHostName event attribute.
func (e *Event) SetIdentHostNameAttr(value string) error { return e.SetAttr("identHostName", value) }

// SetIdentNetBiosAttr sets identNetBios event attribute.
func (e *Event) SetIdentNetBiosAttr(value string) error { return e.SetAttr("identNetBios", value) }

// SetIdentGrpNameAttr sets identGrpName event attribute.
func (e *Event) SetIdentGrpNameAttr(value string) error { return e.SetAttr("identGrpName", value) }

// SetIdentMACAttr sets identMAC event attribute.
func (e *Event) SetIdentMACAttr(value net.HardwareAddr) error {
	return e.SetAttr("identMAC", value.String())
}

// SetVSrcAttr sets vSrc event attribute.
func (e *Event) SetVSrcAttr(value net.IP) error { return e.SetAttr("vSrc", value.String()) }

// SetVSrcNameAttr sets vSrcName event attribute.
func (e *Event) SetVSrcNameAttr(value string) error { return e.SetAttr("vSrcName", value) }

// SetAccountNameAttr sets accountName event attribute.
func (e *Event) SetAccountNameAttr(value string) error { return e.SetAttr("accountName", value) }

// SetSrcBytesAttr sets srcBytes event attribute.
func (e *Event) SetSrcBytesAttr(value int) error {
	return e.SetAttr("srcBytes", strconv.FormatInt(int64(value), 10))
}

// SetDstBytesAttr sets dstBytes event attribute.
func (e *Event) SetDstBytesAttr(value int) error {
	return e.SetAttr("dstBytes", strconv.FormatInt(int64(value), 10))
}

// SetSrcPacketsAttr sets srcPackets event attribute.
func (e *Event) SetSrcPacketsAttr(value int) error {
	return e.SetAttr("srcPackets", strconv.FormatInt(int64(value), 10))
}

// SetDstPacketsAttr sets dstPackets event attribute.
func (e *Event) SetDstPacketsAttr(value int) error {
	return e.SetAttr("dstPackets", strconv.FormatInt(int64(value), 10))
}

// SetTotalPacketsAttr sets totalPackets event attribute.
func (e *Event) SetTotalPacketsAttr(value int) error {
	return e.SetAttr("totalPackets", strconv.FormatInt(int64(value), 10))
}

// SetRoleAttr sets role event attribute.
func (e *Event) SetRoleAttr(value string) error { return e.SetAttr("role", value) }

// SetRealmAttr sets realm event attribute.
func (e *Event) SetRealmAttr(value string) error { return e.SetAttr("realm", value) }

// SetPolicyAttr sets policy event attribute.
func (e *Event) SetPolicyAttr(value string) error { return e.SetAttr("policy", value) }

// SetResourceAttr sets resource event attribute.
func (e *Event) SetResourceAttr(value string) error { return e.SetAttr("resource", value) }

// SetURLAttr sets URL event attribute.
func (e *Event) SetURLAttr(value string) error { return e.SetAttr("url", value) }

// SetGroupIDAttr sets groupID event attribute.
func (e *Event) SetGroupIDAttr(value string) error { return e.SetAttr("groupID", value) }

// SetDomainAttr sets domain event attribute.
func (e *Event) SetDomainAttr(value string) error { return e.SetAttr("domain", value) }

// SetIsLoginEventAttr sets isLoginEvent event attribute.
func (e *Event) SetIsLoginEventAttr(value bool) error {
	return e.SetAttr("isLoginEvent", strconv.FormatBool(value))
}

// SetIsLogoutEventAttr sets isLogoutEvent event attribute.
func (e *Event) SetIsLogoutEventAttr(value bool) error {
	return e.SetAttr("isLogoutEvent", strconv.FormatBool(value))
}

// SetIdentSecondlpAttr sets identSecondlp event attribute.
func (e *Event) SetIdentSecondlpAttr(value net.IP) error {
	return e.SetAttr("identSecondlp", value.String())
}

// SetCalLanguageAttr sets calLanguage event attribute.
func (e *Event) SetCalLanguageAttr(value string) error { return e.SetAttr("calLanguage", value) }

// SetcalCountryOrRegionAttr sets CalCountryOrRegion event attribute.
func (e *Event) SetcalCountryOrRegionAttr(value string) error {
	return e.SetAttr("calCountryOrRegion", value)
}

func (e *Event) String() string {
	return e.buf.String()
}
