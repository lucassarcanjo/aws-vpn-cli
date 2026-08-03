# Homebrew formula that BUILDS FROM SOURCE. No prebuilt binary is ever run as
# root on trust, and the vendored dependency tree means the build needs no
# network inside Homebrew's sandbox.
#
# This file is the source of truth. On a v* tag, .github/workflows/release.yml
# copies it into lucassarcanjo/homebrew-tap with `url` and `sha256` pinned to
# that tag, which is what serves `brew install lucassarcanjo/tap/awsvpn`.
# The placeholder sha256 below is rewritten there; it is never a real digest.
class Awsvpn < Formula
  desc "CLI-first AWS Client VPN for macOS (SAML/SSO), trust-minimal wrapper"
  homepage "https://github.com/lucassarcanjo/aws-vpn-cli"
  url "https://github.com/lucassarcanjo/aws-vpn-cli/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"
  head "https://github.com/lucassarcanjo/aws-vpn-cli.git", branch: "main"

  depends_on "go" => :build
  depends_on :macos

  def install
    ldflags = %W[
      -X github.com/lucassarcanjo/aws-vpn-cli/internal/version.Version=#{version}
      -X github.com/lucassarcanjo/aws-vpn-cli/internal/version.Date=#{time.strftime("%Y-%m-%d")}
    ]
    system "go", "build", *std_go_args(ldflags: ldflags), "."
  end

  def caveats
    <<~EOS
      awsvpn drives the AWS-signed acvc-openvpn binary from the official AWS VPN
      Client, which must be installed:
        https://aws.amazon.com/vpn/client-vpn-download/

      Connect with sudo (no standing privilege by default):
        sudo awsvpn connect <profile>
    EOS
  end

  test do
    assert_match "awsvpn", shell_output("#{bin}/awsvpn version")
  end
end
