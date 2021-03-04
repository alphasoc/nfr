package client

// EventType defines a network event type.
type EventType string

// Telemetry types processed by AlphaSOC.
const (
	EventTypeDNS  EventType = "dns"
	EventTypeIP   EventType = "ip"
	EventTypeHTTP EventType = "http"
)
