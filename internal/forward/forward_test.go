package forward

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in         string
		bind, targ string
	}{
		{"2222:localhost:22", "localhost:2222", "localhost:22"},
		{"0.0.0.0:8080:example.com:80", "0.0.0.0:8080", "example.com:80"},
		{"443:db.internal:5432", "localhost:443", "db.internal:5432"},
	}
	for _, tt := range tests {
		spec, err := Parse(tt.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.in, err)
			continue
		}
		if spec.Bind != tt.bind || spec.Target != tt.targ {
			t.Errorf("Parse(%q) = {%q %q}, want {%q %q}", tt.in, spec.Bind, spec.Target, tt.bind, tt.targ)
		}
	}
}

func TestParseBad(t *testing.T) {
	for _, in := range []string{
		"",
		"22",
		"localhost:22",
		"abc:localhost:22",
		"2222:localhost:0",
		"2222::22",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", in)
		}
	}
}

func TestAllowlist(t *testing.T) {
	a := Allowlist{"localhost:*", "*.internal:22", "192.168.1.?:8080"}
	allowed := []string{
		"localhost:22",
		"localhost:65535",
		"db.internal:22",
		"192.168.1.5:8080",
	}
	for _, target := range allowed {
		if !a.Allows(target) {
			t.Errorf("Allows(%q) = false, want true", target)
		}
	}
	denied := []string{
		"example.com:22",
		"db.internal:23",
		"192.168.1.55:8080",
		"192.168.1.5:8081",
	}
	for _, target := range denied {
		if a.Allows(target) {
			t.Errorf("Allows(%q) = true, want false", target)
		}
	}
}

func TestGlobEdge(t *testing.T) {
	if !globMatch("*", "") {
		t.Error(`globMatch("*", "") = false`)
	}
	if !globMatch("*:*", "a:b:c") {
		t.Error(`globMatch("*:*", "a:b:c") = false; * must cross colons`)
	}
	if globMatch("localhost:*", "localhost") {
		t.Error("globMatch matched missing colon")
	}
	if !globMatch("localhost:*", "localhost:22:extra") {
		// '*' crosses colons, so this matches; documented behavior.
		t.Error(`globMatch("localhost:*", "localhost:22:extra") = false`)
	}
}
