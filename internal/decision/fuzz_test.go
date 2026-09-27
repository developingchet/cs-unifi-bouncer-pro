package decision

import (
	"net/netip"
	"strings"
	"testing"
)

// FuzzParseAndSanitize checks that every accepted value comes back in a
// canonical form that parses to itself and is never a host prefix, which
// UniFi firewall groups reject.
func FuzzParseAndSanitize(f *testing.F) {
	for _, seed := range []string{
		"1.2.3.4", " 1.2.3.4 ", "::ffff:1.2.3.4", "2001:db8::1",
		"10.0.0.0/8", "1.2.3.4/32", "2001:db8::/32", "2001:db8::1/128",
		"1.2.3.4/24", "::ffff:1.2.3.0/120", "", "not-an-ip", "1.2.3.4/33",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		out, isRange, err := ParseAndSanitize(value)
		if err != nil {
			return
		}
		if isRange != strings.Contains(out, "/") {
			t.Fatalf("ParseAndSanitize(%q) = %q, isRange=%v", value, out, isRange)
		}
		if _, ok := HostPrefixAddress(out); ok {
			t.Fatalf("ParseAndSanitize(%q) = %q, a host prefix", value, out)
		}
		again, againRange, err := ParseAndSanitize(out)
		if err != nil || again != out || againRange != isRange {
			t.Fatalf("ParseAndSanitize(%q) = %q, but re-parsing it gives %q, %v, %v",
				value, out, again, againRange, err)
		}
	})
}

// FuzzUnbannablePrivate checks that no private, loopback or link-local
// address can be banned, whichever of its forms the decision carries.
func FuzzUnbannablePrivate(f *testing.F) {
	f.Add([]byte{10, 0, 0, 1})
	f.Add([]byte{192, 168, 1, 1})
	f.Add([]byte{127, 0, 0, 1})
	f.Add([]byte{169, 254, 0, 1})
	f.Add([]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	f.Add([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, raw []byte) {
		addr, ok := netip.AddrFromSlice(raw)
		if !ok {
			return
		}
		addr = addr.Unmap()
		if !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
			return
		}
		value, isRange, err := ParseAndSanitize(addr.String())
		if err != nil {
			t.Fatalf("ParseAndSanitize(%s): %v", addr, err)
		}
		if !Unbannable(value, IsIPv6(value), nil) {
			t.Fatalf("private address %s (sanitized %q, range=%v) is bannable", addr, value, isRange)
		}
	})
}
