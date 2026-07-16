package profile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/config"
)

// buildFixtureHome lays out a fake user home with an AWS profile store and an
// imported .ovpn, mirroring the real on-disk shape.
func buildFixtureHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()

	awsDir := config.OpenVpnConfigsDir(home)
	if err := os.MkdirAll(awsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A real (trimmed) ConnectionProfiles document.
	store := `{"Version":"1","LastSelectedProfileIndex":-1,"ConnectionProfiles":[` +
		`{"ProfileName":"dev","OvpnConfigFilePath":"` + filepath.Join(awsDir, "dev") + `","CvpnEndpointId":"cvpn-endpoint-0123456789abcdef0","CvpnEndpointRegion":"us-east-2","FederatedAuthType":1},` +
		`{"ProfileName":"prod","OvpnConfigFilePath":"` + filepath.Join(awsDir, "prod") + `","CvpnEndpointId":"cvpn-endpoint-0fedcba987654321f","CvpnEndpointRegion":"us-east-2","FederatedAuthType":1}]}`
	if err := os.WriteFile(config.ConnectionProfilesPath(home), []byte(store), 0o644); err != nil {
		t.Fatal(err)
	}

	// An imported config with a real-shaped remote line.
	impDir := config.ImportedProfilesDir(home)
	if err := os.MkdirAll(impDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ovpn := "client\ndev tun\nproto udp\n" +
		"remote cvpn-endpoint-0abc123.prod.clientvpn.eu-west-1.amazonaws.com 443\n" +
		"auth-user-pass\n"
	if err := os.WriteFile(filepath.Join(impDir, "staging.ovpn"), []byte(ovpn), 0o644); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestDiscover(t *testing.T) {
	home := buildFixtureHome(t)
	profiles, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 3 {
		t.Fatalf("got %d profiles, want 3: %+v", len(profiles), profiles)
	}
	// Sorted by name: dev, prod, staging.
	names := []string{profiles[0].Name, profiles[1].Name, profiles[2].Name}
	want := []string{"dev", "prod", "staging"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("names = %v, want %v", names, want)
		}
	}
	if profiles[0].Source != SourceAWS || profiles[0].Region != "us-east-2" {
		t.Errorf("dev = %+v, want AWS/us-east-2", profiles[0])
	}
	staging := profiles[2]
	if staging.Source != SourceImported {
		t.Errorf("staging source = %v, want imported", staging.Source)
	}
	if staging.EndpointID != "cvpn-endpoint-0abc123" || staging.Region != "eu-west-1" {
		t.Errorf("staging endpoint/region = %q/%q", staging.EndpointID, staging.Region)
	}
}

func TestDiscover_EmptyHome(t *testing.T) {
	// No AWS store, no imports: not an error, just empty.
	profiles, err := Discover(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 0 {
		t.Fatalf("expected no profiles, got %+v", profiles)
	}
}

func TestFind(t *testing.T) {
	home := buildFixtureHome(t)
	p, err := Find(home, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if p.EndpointID != "cvpn-endpoint-0fedcba987654321f" {
		t.Errorf("prod endpoint = %q", p.EndpointID)
	}
	if _, err := Find(home, "nope"); err == nil {
		t.Error("expected error for unknown profile")
	}
}

func TestAWSStoreWinsOnCollision(t *testing.T) {
	home := buildFixtureHome(t)
	// Import a profile named "dev" that should be shadowed by the AWS store.
	impDir := config.ImportedProfilesDir(home)
	if err := os.WriteFile(filepath.Join(impDir, "dev.ovpn"), []byte("remote x.clientvpn.us-west-2.amazonaws.com 443\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Find(home, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != SourceAWS {
		t.Errorf("dev should come from the AWS store, got %v", p.Source)
	}
}
