# Homebrew formula that BUILDS FROM SOURCE — no prebuilt binary is ever run as
# root on trust. Drop this into a tap (e.g. larcanjo/homebrew-tap) and
# `brew install larcanjo/tap/awsvpn`.
class Awsvpn < Formula
  desc "CLI-first AWS Client VPN for macOS (SAML/SSO), trust-minimal wrapper"
  homepage "https://github.com/larcanjo/awsvpn"
  url "https://github.com/larcanjo/awsvpn/archive/refs/tags/v0.1.0.tar.gz"
  # sha256 "<filled in at release>"
  license "MIT"
  head "https://github.com/larcanjo/awsvpn.git", branch: "main"

  depends_on "go" => :build
  depends_on :macos

  def install
    ldflags = %W[
      -X github.com/larcanjo/awsvpn/internal/version.Version=#{version}
      -X github.com/larcanjo/awsvpn/internal/version.Date=#{time.strftime("%Y-%m-%d")}
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
