// Package forward parses --fwd specifications and matches requested
// forward targets against the daemon's allowlist.
package forward

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Spec is one parsed --fwd flag: a local listen address and the remote
// target the server dials.
type Spec struct {
	// Bind is the local listen address ("host:port").
	Bind string
	// Target is the remote dial address ("host:port"), resolved on
	// the server side.
	Target string
}

// Parse parses a --fwd value of the form [bind_addr:]port:host:hostport.
// The bind address defaults to localhost.
func Parse(s string) (Spec, error) {
	parts := strings.Split(s, ":")
	// Collect from the right: hostport, host, port, [bind...].
	if len(parts) < 3 {
		return Spec{}, fmt.Errorf("expected [bind_addr:]port:host:hostport, got %q", s)
	}
	hostport := parts[len(parts)-1]
	host := parts[len(parts)-2]
	port := parts[len(parts)-3]
	bind := "localhost"
	if len(parts) > 3 {
		bind = strings.Join(parts[:len(parts)-3], ":")
		if bind == "" {
			bind = "localhost"
		}
	}
	for name, p := range map[string]string{"port": port, "hostport": hostport} {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return Spec{}, fmt.Errorf("bad %s %q in %q", name, p, s)
		}
	}
	if host == "" {
		return Spec{}, fmt.Errorf("empty host in %q", s)
	}
	return Spec{
		Bind:   net.JoinHostPort(bind, port),
		Target: net.JoinHostPort(host, hostport),
	}, nil
}

// Allowlist matches requested targets against glob patterns. A target
// is allowed if it matches any pattern; '*' and '?' match any
// characters including the colon separator (e.g. "localhost:*").
type Allowlist []string

// Allows reports whether target ("host:port") matches any pattern.
func (a Allowlist) Allows(target string) bool {
	for _, pattern := range a {
		if globMatch(pattern, target) {
			return true
		}
	}
	return false
}

// globMatch reports whether name matches the glob pattern. Unlike
// path.Match there is no special separator: '*' and '?' match any
// character including ':'.
func globMatch(pattern, name string) bool {
	px, nx := 0, 0
	nextPx, nextNx := -1, -1 // last '*' position for backtracking
	for px < len(pattern) || nx < len(name) {
		if px < len(pattern) {
			switch pattern[px] {
			case '*':
				nextPx, nextNx = px, nx
				px++
				continue
			case '?':
				if nx < len(name) {
					px++
					nx++
					continue
				}
			default:
				if nx < len(name) && pattern[px] == name[nx] {
					px++
					nx++
					continue
				}
			}
		}
		// Mismatch (or pattern exhausted): backtrack to the last '*'.
		if nextNx >= 0 && nextNx < len(name) {
			px = nextPx + 1
			nx = nextNx + 1
			nextNx++
			continue
		}
		return false
	}
	return true
}
