package transport

import (
	"testing"
)

func FuzzDecodeDNSQName(f *testing.F) {
	// Seed inputs
	f.Add("p0.t2.o100.mzxw6ytboi======.c01.tunnel.example.com", "tunnel.example.com")
	f.Add("p1.t1.o0.onuw4===.client.domain.com", "domain.com")
	f.Add("invalid.string", "domain.com")
	f.Add("p99.t1.o10.badbase32.c1.suffix.org", "suffix.org")

	f.Fuzz(func(t *testing.T, qname, suffix string) {
		// Must not panic on arbitrary malformed inputs
		_, _, _, _, _, _ = DecodeDNSQName(qname, suffix)
	})
}

func FuzzBuildDecoyClientHello(f *testing.F) {
	f.Add("hcaptcha.com", "chrome")
	f.Add("bank.ir", "firefox")
	f.Add("", "none")
	f.Add("a-very-long-domain-name-that-tests-sni-extension-length-boundaries.com", "custom")

	f.Fuzz(func(t *testing.T, sni, preset string) {
		// Must not panic and must produce valid record length
		out := BuildDecoyClientHello(sni, preset)
		if len(out) < 9 {
			t.Fatalf("ClientHello too short: %d", len(out))
		}
	})
}
