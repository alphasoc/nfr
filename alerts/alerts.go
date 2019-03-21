package alerts

import (
	"github.com/alphasoc/nfr/client"
	"github.com/alphasoc/nfr/groups"
)

// AlertMapper maps response to internal alert struct.
type AlertMapper struct {
	groups *groups.Groups
}

// Alert represents alert api struct.
type Alert struct {
	Follow string  `json:"follow"`
	More   bool    `json:"more"`
	Events []Event `json:"events"`
}

// Event from alert.
type Event struct {
	Flags   []string          `json:"flags"`
	Groups  []Group           `json:"groups"`
	Threats map[string]Threat `json:"threats"`

	EventType string `json:"eventType"`

	client.EventUnified
}

func (e *Event) topThreat() (string, Threat) {
	var (
		topID     string
		topThreat Threat
	)

	for tid, threat := range e.Threats {
		if threat.Severity > topThreat.Severity {
			topID = tid
			topThreat = threat
		}
	}

	return topID, topThreat
}

// Threat for event.
type Threat struct {
	Severity    int    `json:"severity"`
	Description string `json:"desc"`
	Policy      bool   `json:"policy"`
}

// Group describe group event belongs to.
type Group struct {
	Label       string `json:"label"`
	Description string `json:"desc"`
}

// NewAlertMapper creates new alert mapper.
func NewAlertMapper(groups *groups.Groups) *AlertMapper {
	return &AlertMapper{groups: groups}
}

// Map maps client response to alert.
func (m *AlertMapper) Map(resp *client.AlertsResponse) *Alert {
	var alert = &Alert{
		Follow: resp.Follow,
		More:   resp.More,
		Events: make([]Event, len(resp.Alerts)),
	}

	for i := range resp.Alerts {
		ev := Event{
			EventType:    resp.Alerts[i].EventType,
			Flags:        resp.Alerts[i].Wisdom.Flags,
			Threats:      make(map[string]Threat),
			EventUnified: resp.Alerts[i].Event,
		}

		for _, threat := range resp.Alerts[i].Threats {
			ev.Threats[threat] = Threat{
				Severity:    resp.Threats[threat].Severity,
				Description: resp.Threats[threat].Title,
				Policy:      resp.Threats[threat].Policy,
			}
		}

		for _, group := range m.groups.FindGroupsBySrcIP(resp.Alerts[i].Event.SrcIP) {
			ev.Groups = append(alert.Events[i].Groups, Group{
				Label:       group.Name,
				Description: group.Label,
			})
		}

		alert.Events[i] = ev
	}
	return alert
}
