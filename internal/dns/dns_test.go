package dns

import (
	"reflect"
	"testing"
)

func TestParsePrimaryService(t *testing.T) {
	// Real `scutil` output shape for State:/Network/Global/IPv4.
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

func TestParseServerAddresses(t *testing.T) {
	// Real `scutil` output shape for a service's DNS dictionary.
	const out = `<dictionary> {
  DomainName : Home
  ServerAddresses : <array> {
    0 : 192.168.15.1
    1 : fe80::ea45:8bff:fe68:af90
  }
  SearchDomains : <array> {
    0 : Home
  }
}`
	got := parseServerAddresses(out)
	want := []string{"192.168.15.1", "fe80::ea45:8bff:fe68:af90"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("servers = %v, want %v", got, want)
	}
}

func TestParseServerAddresses_None(t *testing.T) {
	// A DNS dict with only search domains — no ServerAddresses to capture.
	const out = `<dictionary> {
  SearchDomains : <array> {
    0 : Home
  }
}`
	if got := parseServerAddresses(out); len(got) != 0 {
		t.Errorf("expected no servers, got %v", got)
	}
}
