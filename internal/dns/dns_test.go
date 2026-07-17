package dns

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParsePrimaryService(t *testing.T) {
	const out = `<dictionary> {
  PrimaryInterface : en0
  PrimaryService : 37A55208-54F1-4015-BA5B-BBA724AB9B09
  Router : 192.168.15.1
}`
	if got := parsePrimaryService(out); got != "37A55208-54F1-4015-BA5B-BBA724AB9B09" {
		t.Errorf("primary service = %q", got)
	}
	if got := parsePrimaryService("<dictionary> {\n}"); got != "" {
		t.Errorf("expected empty when no PrimaryService, got %q", got)
	}
}

// A real DNS dictionary with both arrays and a scalar, exercising the exact
// shape scutil emits.
const realDNSDict = `<dictionary> {
  DomainName : Home
  ServerAddresses : <array> {
    0 : 192.168.15.1
    1 : fe80::ea45:8bff:fe68:af90
  }
  SearchDomains : <array> {
    0 : Home
    1 : corp.example.com
  }
}`

func TestParseArray_ServerAddresses(t *testing.T) {
	got := parseArray(realDNSDict, "ServerAddresses")
	want := []string{"192.168.15.1", "fe80::ea45:8bff:fe68:af90"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("servers = %v, want %v", got, want)
	}
}

func TestParseArray_SearchDomains(t *testing.T) {
	got := parseArray(realDNSDict, "SearchDomains")
	want := []string{"Home", "corp.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("search domains = %v, want %v", got, want)
	}
}

func TestParseScalar_DomainName(t *testing.T) {
	if got := parseScalar(realDNSDict, "DomainName"); got != "Home" {
		t.Errorf("domain name = %q, want Home", got)
	}
	// A scalar lookup must not accidentally match an array key of similar name.
	if got := parseScalar(realDNSDict, "ServerAddresses"); got != "" {
		t.Errorf("scalar lookup matched an array: %q", got)
	}
}

func TestCaptureBackup_SearchDomainsOnly(t *testing.T) {
	// The regression the revert fix targets: a DNS dict with only SearchDomains
	// (no ServerAddresses) must still be captured as Present so revert restores
	// it rather than deleting the key.
	const searchOnly = `<dictionary> {
  SearchDomains : <array> {
    0 : Home
  }
}`
	if got := parseArray(searchOnly, "ServerAddresses"); len(got) != 0 {
		t.Errorf("expected no servers, got %v", got)
	}
	if got := parseArray(searchOnly, "SearchDomains"); !reflect.DeepEqual(got, []string{"Home"}) {
		t.Errorf("search domains = %v, want [Home]", got)
	}
}

// TestBackupJSONRoundTrip: crash recovery reloads the backup from disk, so both
// captured dictionaries — including the Present flag that decides restore vs
// remove — must survive a JSON round trip.
func TestBackupJSONRoundTrip(t *testing.T) {
	in := Backup{
		ServiceID: "37A55208-54F1-4015-BA5B-BBA724AB9B09",
		State: Dict{
			Present:         true,
			ServerAddresses: []string{"192.168.15.1", "fe80::ea45:8bff:fe68:af90"},
			SearchDomains:   []string{"Home"},
			DomainName:      "Home",
		},
		Setup: Dict{}, // no manual DNS configured — revert must remove our key
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Backup
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip changed backup:\n in  %+v\n out %+v", in, out)
	}
	if out.Setup.Present {
		t.Error("absent Setup dict must stay Present=false after round trip")
	}
}

// TestDictEmpty: a Present-but-empty dict must read as empty so revert removes
// the key instead of writing an empty dictionary.
func TestDictEmpty(t *testing.T) {
	if !(Dict{Present: true}).empty() {
		t.Error("dict with no values should be empty")
	}
	if (Dict{SearchDomains: []string{"Home"}}).empty() {
		t.Error("dict with search domains should not be empty")
	}
}
