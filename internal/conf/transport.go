package conf

import (
	"fmt"
	"slices"
)

type SNI struct {
	Decoy  string `yaml:"decoy"`
	Preset string `yaml:"preset"`
	Method string `yaml:"method"`
}

type DNS struct {
	Resolver     string `yaml:"resolver"`
	DomainSuffix string `yaml:"domain_suffix"`
	ClientID     string `yaml:"client_id"`
}

type Spoof struct {
	SpoofIP         string `yaml:"spoof_ip"`
	AllowUnverified bool   `yaml:"allow_unverified"`
}

type Selector struct {
	StrategyOrder   []string `yaml:"strategy_order"`
	CooldownSec     int      `yaml:"cooldown_sec"`
	HysteresisRatio float64  `yaml:"hysteresis_ratio"`
}

type TLS struct {
	Enabled            bool     `yaml:"enabled"`
	ServerName         string   `yaml:"server_name"`
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify"`
	CertFile           string   `yaml:"cert_file"`
	KeyFile            string   `yaml:"key_file"`
	CAFile             string   `yaml:"ca_file"`
	MinVersion         string   `yaml:"min_version"` // "1.2", "1.3"
	ALPN               []string `yaml:"alpn"`
}

type Transport struct {
	Protocol string    `yaml:"protocol"`
	Conn     int       `yaml:"conn"`
	KCP      *KCP      `yaml:"kcp"`
	Obfs     *Obfs     `yaml:"obfs"`
	SNI      *SNI      `yaml:"sni"`
	TLS      *TLS      `yaml:"tls"`
	DNS      *DNS      `yaml:"dns"`
	Spoof    *Spoof    `yaml:"spoof"`
	Selector *Selector `yaml:"selector"`
}

func (t *Transport) setDefaults(role string) {
	if t.Conn == 0 {
		t.Conn = 1
	}

	var kcpKey string
	switch t.Protocol {
	case "kcp", "raw-kcp":
		if t.KCP != nil {
			t.KCP.setDefaults(role)
			kcpKey = t.KCP.Key
		}
	}

	if t.Obfs == nil {
		t.Obfs = &Obfs{}
	}
	t.Obfs.setDefaults(kcpKey)

	if t.Protocol == "tls" || t.Protocol == "tls-stream" {
		if t.Obfs != nil && len(t.Obfs.Key) == 0 {
			t.Obfs.Enabled = false
		}
	}

	if t.SNI == nil {
		t.SNI = &SNI{
			Decoy:  "hcaptcha.com",
			Preset: "chrome",
			Method: "wrong_seq",
		}
	}

	if t.TLS == nil {
		t.TLS = &TLS{
			Enabled:            false,
			InsecureSkipVerify: true,
			MinVersion:         "1.3",
			ALPN:               []string{"h2", "http/1.1"},
		}
	}
}

func (t *Transport) validate() []error {
	var errors []error

	validProtocols := []string{
		"kcp", "raw-kcp",
		"stream", "aead-stream",
		"sni-assisted",
		"tls", "tls-stream",
		"asymmetric-spoof",
		"dns-asymmetric",
		"auto",
	}
	if !slices.Contains(validProtocols, t.Protocol) {
		errors = append(errors, fmt.Errorf("transport protocol must be one of: %v", validProtocols))
	}

	if t.Conn < 1 || t.Conn > 256 {
		errors = append(errors, fmt.Errorf("transport conn must be between 1-256 connections"))
	}

	switch t.Protocol {
	case "kcp", "raw-kcp":
		if t.KCP == nil {
			errors = append(errors, fmt.Errorf("transport.kcp configuration is required"))
		} else {
			errors = append(errors, t.KCP.validate()...)
		}
	case "stream", "aead-stream", "sni-assisted", "auto":
		if t.Obfs == nil || len(t.Obfs.Key) == 0 {
			errors = append(errors, fmt.Errorf("transport.obfs.key is required for %s protocol", t.Protocol))
		}
	}

	if t.Obfs != nil {
		mtu := 0
		if t.KCP != nil {
			mtu = t.KCP.MTU
		}
		errors = append(errors, t.Obfs.validate(mtu)...)
	}

	return errors
}
