package dispatch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// SSRF failures. They are distinguished because one of them — a destination
// that resolves to a private address at delivery time having resolved
// publicly at registration — is an attack in progress and deserves an alert,
// while the others are configuration mistakes.
var (
	ErrNotHTTPS       = errors.New("destination must be https")
	ErrPrivateAddress = errors.New("destination resolves to an address that is not publicly routable")
	ErrNoAddress      = errors.New("destination hostname does not resolve")
	ErrRedirect       = errors.New("destination redirected; signed deliveries are never followed")
)

// Guard validates destination URLs and, crucially, re-checks them at the
// moment of delivery.
//
// Validating only at registration is defeated by DNS rebinding: an attacker
// registers a hostname that resolves to a public address for as long as it
// takes to pass the check, then repoints it at 169.254.169.254 and receives
// the cloud metadata service's response in their delivery log. The
// re-resolution here, inside the dialler, is the control that actually holds
// — it happens after the DNS lookup the connection will use, so there is no
// window between checking and connecting.
type Guard struct {
	resolver *net.Resolver

	// extraBlocked lets a deployment refuse ranges beyond the universal ones
	// — a VPC CIDR, say, that is publicly routable in the IANA sense but is
	// still inside the perimeter.
	extraBlocked []netip.Prefix

	// allowPrivate exists for tests and for a self-hosted install whose
	// destinations genuinely are on a private network. It is off by default
	// and the server refuses to enable it in the live environment.
	allowPrivate bool
}

// GuardOptions configure a Guard.
type GuardOptions struct {
	Resolver     *net.Resolver
	BlockedCIDRs []string
	AllowPrivate bool
}

// NewGuard builds a Guard. Unparseable CIDRs are an error rather than a
// silently-ignored line, because a blocklist that quietly does not include
// the range you thought it did is worse than no blocklist.
func NewGuard(o GuardOptions) (*Guard, error) {
	g := &Guard{resolver: o.Resolver, allowPrivate: o.AllowPrivate}
	if g.resolver == nil {
		g.resolver = net.DefaultResolver
	}
	for _, c := range o.BlockedCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("blocked CIDR %q: %w", c, err)
		}
		g.extraBlocked = append(g.extraBlocked, p)
	}
	return g, nil
}

// CheckURL is the registration-time check: scheme, shape, and whether the
// hostname resolves anywhere acceptable right now. Passing it is necessary
// and not sufficient, which is why CheckAddr runs again at delivery.
func (g *Guard) CheckURL(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("destination URL is not a URL: %w", err)
	}
	if u.Scheme != "https" {
		return ErrNotHTTPS
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("destination URL has no host")
	}

	// A literal IP in the URL is checked directly; no lookup can change it.
	if addr, err := netip.ParseAddr(host); err == nil {
		return g.CheckAddr(addr)
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := g.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrNoAddress, host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("%w: %s", ErrNoAddress, host)
	}
	// Every answer must pass. A hostname with one public and one private
	// address is a rebinding attempt dressed as a round-robin.
	for _, a := range addrs {
		if err := g.CheckAddr(a); err != nil {
			return err
		}
	}
	return nil
}

// CheckAddr rejects any address that is not publicly routable.
//
// The list is an allowlist expressed as a denylist of everything else, and it
// is deliberately long. Each entry below has been the subject of a real SSRF
// advisory: link-local for cloud metadata, loopback for admin interfaces
// bound to localhost, unique-local and RFC1918 for lateral movement,
// IPv4-mapped IPv6 for bypassing a check that only looked at v4.
func (g *Guard) CheckAddr(a netip.Addr) error {
	if g.allowPrivate {
		return nil
	}
	if !a.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrPrivateAddress)
	}

	// An IPv4 address arriving as ::ffff:169.254.169.254 must be judged as
	// the IPv4 address it is. Skipping this unmap is the classic bypass.
	a = a.Unmap()

	switch {
	case a.IsLoopback():
		return fmt.Errorf("%w: %s is loopback", ErrPrivateAddress, a)
	case a.IsPrivate():
		return fmt.Errorf("%w: %s is in a private range", ErrPrivateAddress, a)
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return fmt.Errorf("%w: %s is link-local, which is where cloud metadata lives", ErrPrivateAddress, a)
	case a.IsUnspecified():
		return fmt.Errorf("%w: %s is unspecified", ErrPrivateAddress, a)
	case a.IsMulticast():
		return fmt.Errorf("%w: %s is multicast", ErrPrivateAddress, a)
	case a.IsInterfaceLocalMulticast():
		return fmt.Errorf("%w: %s is interface-local", ErrPrivateAddress, a)
	}

	for _, p := range append(g.extraBlocked, universallyBlocked...) {
		if p.Contains(a) {
			return fmt.Errorf("%w: %s is in the blocked range %s", ErrPrivateAddress, a, p)
		}
	}
	return nil
}

// universallyBlocked are the ranges netip's own predicates do not cover.
var universallyBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),      // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),       // documentation
	netip.MustParsePrefix("192.88.99.0/24"),     // deprecated 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),    // documentation
	netip.MustParsePrefix("203.0.113.0/24"),     // documentation
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved
	netip.MustParsePrefix("255.255.255.255/32"), // broadcast
	netip.MustParsePrefix("::/128"),             // unspecified
	netip.MustParsePrefix("64:ff9b::/96"),       // NAT64, which can reach v4 private space
	netip.MustParsePrefix("100::/64"),           // discard-only
	netip.MustParsePrefix("2001:db8::/32"),      // documentation
	netip.MustParsePrefix("fc00::/7"),           // unique local
}

// DialContext is a net.Dialer control hook that re-checks the address the
// connection is about to use.
//
// This is the version that matters. Everything above can be raced: a check
// against a DNS answer, followed by a connection that performs its own
// lookup, leaves a window in which the answer changes. Here the address is
// already resolved and about to be connected to, so there is no window at
// all.
func (g *Guard) DialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addrs, err := g.resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrNoAddress, host, err)
		}

		var lastErr error
		for _, a := range addrs {
			if err := g.CheckAddr(a); err != nil {
				// One bad answer poisons the whole hostname. Trying the next
				// address would let a rebinding attack succeed on its second
				// record.
				return nil, err
			}
		}
		for _, a := range addrs {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("%w: %s", ErrNoAddress, host)
		}
		return nil, lastErr
	}
}
