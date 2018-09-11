package ceflog

import (
	"fmt"
	"io"
	"strings"
)

const (
	cefVersion = 0
)

// Logger can be used to log events in the Common Event Format to an io.Writer.
type Logger struct {
	vendor  string
	product string
	version string

	w io.Writer
}

// New creates a new Logger which logs to the provided io.Writer.
func New(w io.Writer, vendor, product, version string) *Logger {
	return &Logger{
		vendor:  prefixEscape(vendor),
		product: prefixEscape(product),
		version: prefixEscape(version),

		w: w,
	}
}

// LogEvent emits a new audit event to the log.
func (l *Logger) LogEvent(signature, name string, sev Severity, ext Extension) {
	fmt.Fprintf(l.w, "CEF:%d|%s|%s|%s|%s|%s|%d|%s\n",
		cefVersion,
		l.vendor,
		l.product,
		l.version,
		prefixEscape(signature),
		prefixEscape(name),
		sev,
		ext,
	)
}

var prefixEscaper = strings.NewReplacer(
	"\n", `\n`,
	`\`, `\\`,
	`|`, `\|`,
)

func prefixEscape(input string) string {
	return prefixEscaper.Replace(input)
}

var extensionEscaper = strings.NewReplacer(
	`\`, `\\`,
	"\n", `\n`,
	`=`, `\=`,
)

func extensionEscape(input string) string {
	return extensionEscaper.Replace(input)
}

// Severity represents the severity level of logged events.
type Severity int

// Sev converts an integer into a Severity level. CEF only allows severity
// levels between 0 and 10. If the input is less than 0 then it will be clamped
// to 0. If the input is greater than 10 then it will be clamped to 10.
func Sev(s int) Severity {
	if s < 0 {
		s = 0
	} else if s > 10 {
		s = 10
	}

	return Severity(s)
}

// An Extension is the part of the event which can contain extra metadata to be
// added to the log. It should not be created without using the Ext function.
type Extension []Pair

// A Pair is a single piece of metadata which can be added to the event. It
// should never be directly used by the user.
type Pair struct {
	Key   string
	Value string
}

func (e Extension) String() string {
	var pairs []string

	for _, p := range e {
		key := p.Key
		value := extensionEscape(p.Value)

		pairs = append(pairs, fmt.Sprintf("%s=%s", key, value))
	}

	return strings.Join(pairs, " ")
}

// Ext creates an extension which can be added to a log event. It takes a
// pairwise list of repeated key-values. CEF defines a specific set of valid
// keys. This library does not check for their validity.
func Ext(pairs ...string) Extension {
	if len(pairs)%2 != 0 {
		panic("pairs length must be even!")
	}

	var e Extension

	for i := 0; i < len(pairs); i = i + 2 {
		e = append(e, Pair{
			Key:   pairs[i],
			Value: pairs[i+1],
		})
	}

	return e
}
