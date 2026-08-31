package session

import (
	"net"
	"net/netip"
	"strconv"
)

// ParseAddrPort parses a bind or external address given as "ip:port"
// or ":port". An empty host selects the IPv6 unspecified address
// (::), matching the endpoint's default dual-stack bind; "0.0.0.0:0"
// selects IPv4-only with a kernel-chosen port.
func ParseAddrPort(s string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var addr netip.Addr
	if host == "" {
		addr = netip.IPv6Unspecified()
	} else {
		addr, err = netip.ParseAddr(host)
		if err != nil {
			return netip.AddrPort{}, err
		}
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}