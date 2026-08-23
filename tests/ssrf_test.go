package tests

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
)

func TestSSRFGuardRefusesAddressesThatAreNotPubliclyRoutable(t *testing.T) {
	g, err := dispatch.NewGuard(dispatch.GuardOptions{})
	mustNoErr(t, err, "building the guard")

	blocked := []string{
		"127.0.0.1",       // loopback: admin interfaces bound to localhost
		"::1",             //
		"169.254.169.254", // the cloud metadata service, the classic target
		"fe80::1",         // link-local v6
		"10.0.0.1",        // RFC1918
		"172.16.5.4",      //
		"192.168.1.1",     //
		"0.0.0.0",         //
		"100.64.0.1",      // carrier-grade NAT
		"198.18.0.1",      // benchmarking
		"224.0.0.1",       // multicast
		"255.255.255.255", // broadcast
		"fc00::1",         // unique local
		"64:ff9b::a00:1",  // NAT64, which reaches v4 private space

		// The bypass worth testing on its own: an IPv4 address presented as
		// IPv4-mapped IPv6. A check that looks only at the v6 predicates
		// waves this straight through to the metadata service.
		"::ffff:169.254.169.254",
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.1",
	}
	for _, s := range blocked {
		a := netip.MustParseAddr(s)
		if err := g.CheckAddr(a); !errors.Is(err, dispatch.ErrPrivateAddress) {
			t.Errorf("CheckAddr(%s) = %v; it must be refused", s, err)
		}
	}

	for _, s := range []string{"8.8.8.8", "1.1.1.1", "102.89.34.7", "2606:4700:4700::1111"} {
		if err := g.CheckAddr(netip.MustParseAddr(s)); err != nil {
			t.Errorf("CheckAddr(%s) = %v; a public address must be allowed", s, err)
		}
	}
}

func TestSSRFGuardRequiresHTTPS(t *testing.T) {
	g, err := dispatch.NewGuard(dispatch.GuardOptions{})
	mustNoErr(t, err, "building the guard")
	ctx := context.Background()

	if err := g.CheckURL(ctx, "http://example.com/hooks"); !errors.Is(err, dispatch.ErrNotHTTPS) {
		t.Errorf("plain http was accepted: %v", err)
	}
	// The domain-level check rejects it too, so the API produces a good
	// message before the guard is even consulted.
	if err := domain.ValidateDestinationURL("http://example.com/hooks"); err == nil {
		t.Error("domain validation accepted plain http")
	}
	if err := domain.ValidateDestinationURL("https://user:pass@example.com/hooks"); err == nil {
		t.Error("a URL embedding credentials was accepted")
	}
	if err := domain.ValidateDestinationURL("https://example.com/hooks\r\nX-Injected: 1"); err == nil {
		t.Error("a URL containing a line break was accepted")
	}
}

func TestSSRFGuardChecksAtDeliveryTimeNotOnlyAtRegistration(t *testing.T) {
	// Validating only at registration is defeated by rebinding: the hostname
	// resolves publicly long enough to pass the check, then repoints at the
	// metadata service before the first delivery. The dialler below is the
	// control that actually holds, because it runs after the lookup the
	// connection will use.
	g, err := dispatch.NewGuard(dispatch.GuardOptions{})
	mustNoErr(t, err, "building the guard")

	dial := g.DialContext(&net.Dialer{})
	// localhost resolves to a loopback address, so the dialler must refuse
	// before any connection is attempted — regardless of what any earlier
	// check concluded.
	_, err = dial(context.Background(), "tcp", "localhost:80")
	if !errors.Is(err, dispatch.ErrPrivateAddress) {
		t.Fatalf("the delivery-time dialler connected to a private address: %v", err)
	}
}

func TestSSRFGuardExtraBlockedRanges(t *testing.T) {
	// A VPC CIDR is publicly routable in the IANA sense and still inside the
	// perimeter, so a deployment must be able to add its own.
	g, err := dispatch.NewGuard(dispatch.GuardOptions{BlockedCIDRs: []string{"203.0.200.0/24"}})
	mustNoErr(t, err, "building the guard")
	if err := g.CheckAddr(netip.MustParseAddr("203.0.200.5")); !errors.Is(err, dispatch.ErrPrivateAddress) {
		t.Errorf("a deployment-specific blocked range was not enforced: %v", err)
	}

	// A malformed CIDR is an error rather than a silently ignored line: a
	// blocklist that quietly omits the range you thought it had is worse than
	// no blocklist.
	if _, err := dispatch.NewGuard(dispatch.GuardOptions{BlockedCIDRs: []string{"not-a-cidr"}}); err == nil {
		t.Error("an unparseable blocked CIDR was accepted")
	}
}
