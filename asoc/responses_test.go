package asoc

import "testing"

func TestEventsRespSmall(t *testing.T) {
	eventOne := EventDetail{
		Type:  "alert",
		Risk:  1,
		FQDN:  "alphasoc.com",
		IP:    "127.0.0.1",
		QType: "TXT",
		Ts:    []string{"2015-06-09T16:54:59Z"},
	}

	expected := "2015-06-09T16:54:59Z;127.0.0.1;TXT;alphasoc.com;1;;"

	resp := EventsResp{Events: []EventDetail{eventOne}}
	events := resp.Strings()

	if l := len(events); l != 1 {
		t.Fatalf("Expected one response, but received %d", l)
	}

	if expected != events[0] {
		t.Fatalf("Response: expected %q, got %q", expected, events[0])
	}
}

func TestEventsRespEmpty(t *testing.T) {
	eventOne := EventDetail{
		Type:  "alert",
		Risk:  2,
		IP:    "127.0.0.1",
		QType: "TXT",
	}

	resp := EventsResp{Events: []EventDetail{eventOne}}
	events := resp.Strings()
	if len(events) != 0 {
		t.Fatalf("Expected empty response")
	}
}

func TestEventsRespMultiFlag(t *testing.T) {
	eventOne := EventDetail{
		Type:  "alert",
		Risk:  3,
		FQDN:  "alphasoc.com",
		IP:    "127.0.0.1",
		QType: "TXT",
		Flags: []string{"flag1", "flag2"},
		Ts:    []string{"2015-06-09T16:54:59Z"},
	}

	expected := "2015-06-09T16:54:59Z;127.0.0.1;TXT;alphasoc.com;3;;flag1,flag2"

	resp := EventsResp{Events: []EventDetail{eventOne}}
	events := resp.Strings()

	if l := len(events); l != 1 {
		t.Fatalf("Expected one response, but received %d", l)
	}

	if expected != events[0] {
		t.Fatalf("Response: expected %q, got %q", expected, events[0])
	}
}

func TestEventsRespDefinition(t *testing.T) {

	eventOne := EventDetail{
		Type:    "alert",
		Risk:    4,
		FQDN:    "alphasoc.com",
		IP:      "127.0.0.1",
		QType:   "TXT",
		Ts:      []string{"2015-06-09T16:54:59Z"},
		Flags:   []string{"flag1"},
		Threats: []string{"maniacs"},
	}

	threats := map[string]ThreatInfo{
		"maniacs": ThreatInfo{Title: "site maintained by hackers", Severity: 666},
	}

	expected := "2015-06-09T16:54:59Z;127.0.0.1;TXT;alphasoc.com;4;site maintained by hackers;flag1"

	resp := EventsResp{Events: []EventDetail{eventOne}, Threats: threats}
	events := resp.Strings()

	if l := len(events); l != 1 {
		t.Fatalf("Expected one response, but received %d", l)
	}

	if expected != events[0] {
		t.Fatalf("Response: expected %q, got %q", expected, events[0])
	}
}

func TestEventsRespMulti(t *testing.T) {
	eventOne := EventDetail{
		Type:    "alert",
		Risk:    5,
		FQDN:    "alphasoc.com",
		IP:      "127.0.0.1",
		QType:   "TXT",
		Ts:      []string{"2015-06-09T16:54:59Z", "2015-06-09T16:55:19Z"},
		Flags:   []string{"hackers"},
		Threats: []string{"maniacs", "porn"},
	}

	eventTwo := EventDetail{
		Type:    "alert",
		Risk:    6,
		FQDN:    "google.com",
		IP:      "127.0.1.1",
		QType:   "A",
		Ts:      []string{"2015-06-09T16:14:59Z", "2015-06-09T16:11:59Z"},
		Flags:   []string{"google", "gmail", "dancers"},
		Threats: []string{"search_engine", "unsupported"},
	}

	threats := map[string]ThreatInfo{
		"maniacs":       ThreatInfo{Title: "site maintained by hackers", Severity: 666},
		"porn":          ThreatInfo{Title: "possible boobs", Severity: 1},
		"search_engine": ThreatInfo{Title: "search engine", Severity: 2},
	}

	resp := EventsResp{Events: []EventDetail{eventOne, eventTwo}, Threats: threats}

	expected := []string{
		"2015-06-09T16:54:59Z;127.0.0.1;TXT;alphasoc.com;5;site maintained by hackers,possible boobs;hackers",
		"2015-06-09T16:55:19Z;127.0.0.1;TXT;alphasoc.com;5;site maintained by hackers,possible boobs;hackers",
		"2015-06-09T16:14:59Z;127.0.1.1;A;google.com;6;search engine,;google,gmail,dancers",
		"2015-06-09T16:11:59Z;127.0.1.1;A;google.com;6;search engine,;google,gmail,dancers",
	}

	str := resp.Strings()

	if len(str) != len(expected) {
		t.Fatalf("Expected %d responses, but received %d", len(expected), len(str))
	}

	for i := range str {
		if str[i] != expected[i] {
			t.Fatalf("Response: expected %q, got %q", expected[i], str[i])
		}
	}
}
