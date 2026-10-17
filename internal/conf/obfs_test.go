package conf

import (
	"net"
	"testing"

	"github.com/arashmh13/paqet-ngv2/internal/obfs"
)

func boolPtr(b bool) *bool { return &b }

func TestObfsDefaultsEnabledAndFallsBackToKCPKey(t *testing.T) {
	o := &Obfs{}
	o.setDefaults("kcp-key")

	if !o.Enabled {
		t.Fatalf("obfuscation should be enabled by default")
	}
	if o.Key != "kcp-key" {
		t.Fatalf("key = %q, want it to fall back to the kcp key", o.Key)
	}
	if o.MaxPad != 64 {
		t.Fatalf("maxpad = %d, want 64", o.MaxPad)
	}
}

func TestObfsDefaultsRespectExplicitDisable(t *testing.T) {
	o := &Obfs{Enabled_: boolPtr(false), Key: "own-key", MaxPad: 10}
	o.setDefaults("kcp-key")

	if o.Enabled {
		t.Fatalf("obfuscation should stay disabled when explicitly set")
	}
	if o.Key != "own-key" {
		t.Fatalf("key = %q, want the explicitly configured key", o.Key)
	}
	if o.MaxPad != 10 {
		t.Fatalf("maxpad = %d, want 10", o.MaxPad)
	}
}

func TestObfsValidate(t *testing.T) {
	tests := []struct {
		name    string
		kcpKey  string
		obfs    Obfs
		mtu     int
		wantErr bool
	}{
		{name: "enabled without any key", kcpKey: "", obfs: Obfs{}, mtu: 1350, wantErr: true},
		{name: "defaults are valid", kcpKey: "secret", obfs: Obfs{}, mtu: 1350, wantErr: false},
		{name: "frame exceeds max frame", kcpKey: "secret", obfs: Obfs{}, mtu: 1500, wantErr: true},
		{name: "negative padding", kcpKey: "secret", obfs: Obfs{MaxPad: -1}, mtu: 1350, wantErr: true},
		{name: "disabled ignores missing key", kcpKey: "", obfs: Obfs{Enabled_: boolPtr(false)}, mtu: 1350, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := tt.obfs
			o.setDefaults(tt.kcpKey)
			errs := o.validate(tt.mtu)
			if tt.wantErr && len(errs) == 0 {
				t.Fatalf("validate() = nil, want an error")
			}
			if !tt.wantErr && len(errs) != 0 {
				t.Fatalf("validate() = %v, want no error", errs)
			}
		})
	}
}

func TestObfsWrap(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()

	disabled := &Obfs{Enabled: false}
	wrapped, err := disabled.Wrap(conn)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}
	if wrapped != conn {
		t.Fatalf("disabled obfuscation should return the original connection")
	}

	enabled := &Obfs{Enabled: true, Key: "secret", MaxPad: 32}
	wrapped, err = enabled.Wrap(conn)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}
	if _, ok := wrapped.(*obfs.Conn); !ok {
		t.Fatalf("enabled obfuscation should return an *obfs.Conn, got %T", wrapped)
	}
}
