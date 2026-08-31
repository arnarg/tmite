// Package discovery centralizes the shared iroh infrastructure
// configuration (relay map, pkarr HTTP endpoint, DNS discovery origin) so
// the serve and unlock commands build identical option sets from the
// same flags. All three knobs default to the n0 production
// infrastructure; overriding them points both sides at self-hosted
// relays and an iroh-dns-server instance (see cmd/iroh-relay and
// cmd/iroh-dns-server in go-iroh), which fleet deployments need because
// the public n0 relays rate-limit traffic.
package discovery

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

// Config selects the iroh infrastructure. The zero value is the number0
// production default: default relay map, n0 pkarr relay, n0 DNS origin.
type Config struct {
	// Relays lists custom relay URLs (home relays for this endpoint).
	// Empty falls back to relay.ModeDefault().
	Relays []string
	// PkarrURL is a custom pkarr HTTP relay URL for publishing and
	// resolving. Empty uses the n0 production pkarr relay.
	PkarrURL string
	// DNSOrigin is a custom DNS discovery origin for the TXT-record
	// resolver. Empty uses dns.N0DNSEndpointOriginProd.
	DNSOrigin string
}

// RelayMode returns the relay mode for the config: a custom map over the
// listed relay URLs, or the default production map when none are given.
func RelayMode(c Config) (relay.Mode, error) {
	if len(c.Relays) == 0 {
		return relay.ModeDefault(), nil
	}
	urls := make([]netaddr.RelayURL, 0, len(c.Relays))
	for _, s := range c.Relays {
		u, err := netaddr.ParseRelayURL(s)
		if err != nil {
			return relay.Mode{}, fmt.Errorf("discovery: bad relay URL %q: %w", s, err)
		}
		urls = append(urls, u)
	}
	return relay.ModeCustomURLs(urls...), nil
}

// NewPublisher returns a pkarr publisher for sk: custom relay URL when
// configured, the n0 production relay otherwise.
func NewPublisher(c Config, sk key.SecretKey) (*iroh.PkarrPublisher, error) {
	if c.PkarrURL != "" {
		if err := checkHTTPURL(c.PkarrURL); err != nil {
			return nil, err
		}
		return iroh.NewPkarrPublisher(sk, c.PkarrURL, nil)
	}
	return iroh.N0PkarrPublisher(sk, nil)
}

// NewResolvers returns the address-lookup services for resolving server
// IDs: the pkarr HTTP view (freshest, what the server publishes to) and
// the DNS TXT view (may lag slightly). Both follow the configured
// endpoints; the defaults are the n0 production services.
func NewResolvers(c Config) (*iroh.AddressLookupServices, error) {
	lookup := &iroh.AddressLookupServices{}
	if c.PkarrURL != "" {
		if err := checkHTTPURL(c.PkarrURL); err != nil {
			return nil, err
		}
		if res, err := iroh.NewPkarrResolver(c.PkarrURL, nil); err == nil {
			lookup.AddResolver(res)
		}
	} else if res, err := iroh.N0PkarrResolver(nil); err == nil {
		lookup.AddResolver(res)
	}
	origin := c.DNSOrigin
	if origin == "" {
		origin = dns.N0DNSEndpointOriginProd
	}
	lookup.AddResolver(iroh.NewDNSAddressLookup(origin, nil))
	return lookup, nil
}

// ResolveID looks up addressing for id across the configured services
// and returns a dialable EndpointAddr. Resolution is bounded at 10s so
// dial-retry loops cycle instead of parking on one slow resolver.
func ResolveID(ctx context.Context, lookup *iroh.AddressLookupServices, id key.EndpointID) (netaddr.EndpointAddr, error) {
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var lastErr error
	found := false
	for item, err := range lookup.Resolve(rctx, id) {
		if err != nil {
			lastErr = err
			continue
		}
		addr := item.Addr()
		if !addr.IsEmpty() {
			return addr, nil
		}
		found = true
	}
	if lastErr != nil {
		return netaddr.EndpointAddr{}, fmt.Errorf("no address for %s: %w", id.Short(), lastErr)
	}
	if found {
		return netaddr.EndpointAddr{}, fmt.Errorf("address for %s had no usable paths", id.Short())
	}
	return netaddr.EndpointAddr{}, fmt.Errorf("no address found for %s (is it online?)", id.Short())
}

// checkHTTPURL rejects URLs without an http(s) scheme up front, so a
// mistyped flag fails at startup instead of at first publish/resolve.
func checkHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("discovery: bad URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("discovery: URL %q must be http(s)", raw)
	}
	return nil
}
