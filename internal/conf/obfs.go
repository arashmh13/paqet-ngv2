package conf

import (
	"fmt"
	"net"

	"github.com/arashmh13/paqet-ngv2/internal/obfs"
)

// Obfs configures the datagram obfuscation layer that shields the KCP
// transport from deep packet inspection. It encrypts and randomises the
// length of every packet that leaves the raw socket, which removes the
// protocol fingerprint and the size signature that filtering middleboxes
// rely on to detect and block the tunnel.
type Obfs struct {
	Enabled_ *bool  `yaml:"enabled"`
	Key      string `yaml:"key"`
	MaxPad   int    `yaml:"maxpad"`

	Enabled bool `yaml:"-"`
}

func (o *Obfs) setDefaults(kcpKey string) {
	if o.Enabled_ != nil {
		o.Enabled = *o.Enabled_
	} else {
		o.Enabled = true
	}

	if o.Key == "" {
		o.Key = kcpKey
	}

	if o.MaxPad == 0 {
		o.MaxPad = 64
	}
}

func (o *Obfs) validate(mtu int) []error {
	var errors []error

	if o.MaxPad < 0 || o.MaxPad > 512 {
		errors = append(errors, fmt.Errorf("obfs maxpad must be between 0-512 bytes"))
	}

	if o.Enabled {
		if o.Key == "" {
			errors = append(errors, fmt.Errorf("obfs key is required when obfuscation is enabled (set obfs.key or kcp.key)"))
		}
		if max := mtu + obfs.Overhead + o.MaxPad; max > obfs.MaxFrame {
			errors = append(errors, fmt.Errorf("obfs frame size (%d) exceeds the maximum of %d bytes: lower kcp.mtu (%d) or obfs.maxpad (%d)", max, obfs.MaxFrame, mtu, o.MaxPad))
		}
	}

	return errors
}

// Wrap returns conn wrapped in the obfuscation layer, or conn unchanged
// when obfuscation is disabled.
func (o *Obfs) Wrap(conn net.PacketConn) (net.PacketConn, error) {
	if o == nil || !o.Enabled {
		return conn, nil
	}
	return obfs.New(conn, []byte(o.Key), o.MaxPad)
}
