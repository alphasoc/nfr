package AlphaSocAPI

type Event struct {
	timestamp        string
	ip               string
	recordType       string
	domain           string
	severity         string
	threatDefinition string
	flags            []string
}

func (e *Event) String() string {
	return ""
}

//timestamp;ip;record_type;domain;severity;threat_definition;flags
