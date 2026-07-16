// Package profile discovers the VPN profiles a user can connect to. It merges
// the official AWS VPN Client's profile store (read strictly read-only) with any
// raw .ovpn files the user imported into awsvpn's own state directory. All
// parsing is pure and file access is confined to reads, so discovery is safe to
// run and easy to test against a fixture directory.
package profile

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/config"
)

// Source identifies where a profile was discovered.
type Source string

const (
	// SourceAWS is the official AWS VPN Client's profile store.
	SourceAWS Source = "aws"
	// SourceImported is a raw .ovpn file imported via `awsvpn import`.
	SourceImported Source = "imported"
)

// Profile is a connectable endpoint.
type Profile struct {
	Name       string
	OvpnPath   string
	EndpointID string
	Region     string
	Source     Source
}

// awsProfileStore mirrors the official client's ConnectionProfiles JSON. We read
// only the fields we need and ignore the rest.
type awsProfileStore struct {
	ConnectionProfiles []struct {
		ProfileName        string `json:"ProfileName"`
		OvpnConfigFilePath string `json:"OvpnConfigFilePath"`
		CvpnEndpointID     string `json:"CvpnEndpointId"`
		CvpnEndpointRegion string `json:"CvpnEndpointRegion"`
	} `json:"ConnectionProfiles"`
}

// Discover returns the merged, de-duplicated, name-sorted list of profiles for
// the given user home. AWS-store profiles take precedence over imported ones of
// the same name. Missing stores are not an error — a user may have only imported
// profiles, or only the AWS app.
func Discover(home string) ([]Profile, error) {
	byName := map[string]Profile{}

	imported, err := discoverImported(home)
	if err != nil {
		return nil, err
	}
	for _, p := range imported {
		byName[p.Name] = p
	}

	aws, err := discoverAWS(home)
	if err != nil {
		return nil, err
	}
	for _, p := range aws {
		byName[p.Name] = p // AWS store wins on name collision
	}

	out := make([]Profile, 0, len(byName))
	for _, p := range byName {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Find returns the named profile, or an error naming the available profiles.
func Find(home, name string) (Profile, error) {
	profiles, err := Discover(home)
	if err != nil {
		return Profile{}, err
	}
	for _, p := range profiles {
		if p.Name == name {
			return p, nil
		}
	}
	if len(profiles) == 0 {
		return Profile{}, fmt.Errorf("no profile %q found (no profiles configured — add one in the AWS VPN Client or run `awsvpn import <file.ovpn>`)", name)
	}
	names := make([]string, len(profiles))
	for i, p := range profiles {
		names[i] = p.Name
	}
	return Profile{}, fmt.Errorf("no profile %q found; available: %s", name, strings.Join(names, ", "))
}

func discoverAWS(home string) ([]Profile, error) {
	path := config.ConnectionProfilesPath(home)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil // official client not installed / no profiles yet
	}
	if err != nil {
		return nil, fmt.Errorf("reading AWS profile store: %w", err)
	}
	var store awsProfileStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("parsing AWS profile store %s: %w", path, err)
	}
	var out []Profile
	for _, p := range store.ConnectionProfiles {
		if p.ProfileName == "" {
			continue
		}
		out = append(out, Profile{
			Name:       p.ProfileName,
			OvpnPath:   p.OvpnConfigFilePath,
			EndpointID: p.CvpnEndpointID,
			Region:     p.CvpnEndpointRegion,
			Source:     SourceAWS,
		})
	}
	return out, nil
}

func discoverImported(home string) ([]Profile, error) {
	dir := config.ImportedProfilesDir(home)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading imported profiles: %w", err)
	}
	var out []Profile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".ovpn") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		name := strings.TrimSuffix(e.Name(), ".ovpn")
		endpoint, region := endpointFromOvpn(path)
		out = append(out, Profile{
			Name:       name,
			OvpnPath:   path,
			EndpointID: endpoint,
			Region:     region,
			Source:     SourceImported,
		})
	}
	return out, nil
}

// endpointFromOvpn does a best-effort read of the endpoint id and region from a
// config's `remote` line, e.g.
//
//	remote cvpn-endpoint-0123456789abcdef0.prod.clientvpn.us-east-2.amazonaws.com 443
//
// It is informational only (used for `list`); a parse miss just leaves the
// fields blank.
func endpointFromOvpn(path string) (endpoint, region string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "remote" {
			continue
		}
		return parseRemoteHost(fields[1])
	}
	return "", ""
}

// parseRemoteHost pulls the endpoint id and region out of an AWS Client VPN
// remote hostname of the form <endpoint-id>.<...>.clientvpn.<region>.amazonaws.com.
func parseRemoteHost(host string) (endpoint, region string) {
	labels := strings.Split(host, ".")
	if len(labels) > 0 && strings.HasPrefix(labels[0], "cvpn-endpoint-") {
		endpoint = labels[0]
	}
	for i, l := range labels {
		if l == "clientvpn" && i+1 < len(labels) {
			region = labels[i+1]
			break
		}
	}
	return endpoint, region
}
