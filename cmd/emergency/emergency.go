package emergency

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/arashmh13/paqet-ngv2/internal/ng/dns"
	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
)

var (
	listenAddr           string
	resolverAddr         string
	domainSuffix         string
	keyStr               string
	keyFile              string
	clientID             string
	messageStr           string
	timeoutSec           int
	scanResolvers        string
	scanCacheFile        string
	bootstrapIP          string
	bootstrapPort        int
	bootstrapMode        string
	bootstrapCertFile    string
	bootstrapKeyFile     string
	bootstrapPin         string
	bootstrapConfigFile  string
	disableBootstrap     bool
	serverID             string
	serverSecretFile     string
	legacySingleServer   bool
	authorizedServersCfg string
	protocolV4           bool
)

// AuthorizedServersConfigFile is the on-disk JSON schema for the explicit
// multi-server client authorization set. Raw response secrets MUST NOT be embedded;
// entries reference protected credential files instead.
type AuthorizedServersConfigFile struct {
	Version           int                         `json:"version"`
	Protocol          string                      `json:"protocol"` // must be "v4" for the Phase 19 multi-server construction
	Generation        uint64                      `json:"generation,omitempty"`
	AuthorizedServers []AuthorizedServerFileEntry `json:"authorized_servers"`
}

type AuthorizedServerFileEntry struct {
	ServerID   string `json:"server_id"`
	SecretFile string `json:"secret_file"`
}

func init() {
	Cmd.AddCommand(serverCmd)
	Cmd.AddCommand(sendCmd)
	Cmd.AddCommand(scanCmd)

	serverCmd.Flags().StringVar(&listenAddr, "addr", ":53", "Authoritative DNS listening UDP and TCP address")
	serverCmd.Flags().StringVar(&domainSuffix, "domain", "tunnel.paqet-ngv2.example", "Delegated child domain suffix")
	serverCmd.Flags().StringVar(&keyFile, "key-file", "", "Path to file containing 32-byte shared key (prefer over --key)")
	serverCmd.Flags().StringVar(&keyStr, "key", "", "Base64 or hex 32-byte shared key (prefer --key-file or $PAQET_EMERGENCY_KEY to prevent process argument exposure)")
	serverCmd.Flags().StringVar(&serverID, "server-id", "", "Authoritative server cryptographic identity (mandatory in multi-server mode)")
	serverCmd.Flags().StringVar(&serverSecretFile, "server-secret-file", "", "Path to file containing dedicated 32-byte server response secret (mandatory in multi-server mode)")
	serverCmd.Flags().BoolVar(&legacySingleServer, "legacy-single-server", false, "Run in legacy single-server mode using PSK only (incompatible with multi-authoritative)")
	serverCmd.Flags().BoolVar(&protocolV4, "protocol-v4", false, "Speak v4 (PAQD) framing with per-session random seed keying (requires dedicated per-server response secret)")
	serverCmd.Flags().StringVar(&bootstrapIP, "bootstrap-ip", "", "Candidate recovery IP advertised in bootstrap responses (required if --bootstrap-config and --disable-bootstrap are not set)")
	serverCmd.Flags().IntVar(&bootstrapPort, "bootstrap-port", 18089, "Candidate recovery port advertised in bootstrap responses")
	serverCmd.Flags().StringVar(&bootstrapMode, "bootstrap-mode", "aead-stream", "Candidate recovery transport mode advertised in bootstrap responses")
	serverCmd.Flags().StringVar(&bootstrapCertFile, "bootstrap-cert", "", "Path to certificate file for TLS candidate fingerprint computation")
	serverCmd.Flags().StringVar(&bootstrapKeyFile, "bootstrap-key-file", "", "Path to key file for AEAD/Raw-KCP candidate fingerprint computation")
	serverCmd.Flags().StringVar(&bootstrapPin, "bootstrap-pin", "", "Explicit canonical SHA256:<64 hex> identity pin")
	serverCmd.Flags().StringVar(&bootstrapConfigFile, "bootstrap-config", "", "Path to JSON file containing candidate endpoint records")
	serverCmd.Flags().BoolVar(&disableBootstrap, "disable-bootstrap", false, "Run messaging-only emergency server without recovery candidate endpoints (safe fail-closed state)")

	sendCmd.Flags().StringVar(&resolverAddr, "resolver", "8.8.8.8:53", "Recursive DNS resolver address (e.g. 8.8.8.8:53)")
	sendCmd.Flags().StringVar(&domainSuffix, "domain", "tunnel.paqet-ngv2.example", "Delegated child domain suffix")
	sendCmd.Flags().StringVar(&keyFile, "key-file", "", "Path to file containing 32-byte shared key (prefer over --key)")
	sendCmd.Flags().StringVar(&keyStr, "key", "", "Base64 or hex 32-byte shared key (prefer --key-file or $PAQET_EMERGENCY_KEY to prevent process argument exposure)")
	sendCmd.Flags().StringVar(&serverID, "server-id", "", "Expected authoritative server ID to authorize (single-server convenience path)")
	sendCmd.Flags().StringVar(&serverSecretFile, "server-secret-file", "", "Path to file containing server response secret (single-server convenience path)")
	sendCmd.Flags().BoolVar(&legacySingleServer, "legacy-single-server", false, "Run in legacy single-server mode using PSK only")
	sendCmd.Flags().StringVar(&authorizedServersCfg, "authorized-servers-config", "", "Path to JSON file defining the explicit multi-server authorized set (v4 protocol; schema: version, protocol, generation, authorized_servers[{server_id, secret_file}])")
	sendCmd.Flags().StringVar(&clientID, "client-id", "c01", "Client ID string (max 4 chars)")
	sendCmd.Flags().StringVarP(&messageStr, "message", "m", "EMERGENCY_PING", "Application payload to transmit")
	sendCmd.Flags().IntVar(&timeoutSec, "timeout", 5, "Timeout in seconds for response")

	scanCmd.Flags().StringVar(&scanResolvers, "resolvers", "", "Comma-separated resolver IPs (default: system + public resolvers)")
	scanCmd.Flags().StringVar(&domainSuffix, "domain", "tunnel.paqet-ngv2.example", "Target domain suffix")
	scanCmd.Flags().StringVar(&scanCacheFile, "cache", "/tmp/resolver_cache.json", "JSON cache file path")
	scanCmd.Flags().IntVar(&timeoutSec, "timeout", 2, "Timeout per probe in seconds")
}

// Cmd is the root emergency command.
var Cmd = &cobra.Command{
	Use:   "emergency",
	Short: "Authenticated emergency messaging and signaling over recursive DNS",
}

func computeCertFingerprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("read cert file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block from %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}
	digest := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("SHA256:%x", digest), nil
}

func parseKeyBytes(rawStr string) ([]byte, error) {
	rawStr = strings.TrimSpace(rawStr)
	if b, err := base64.StdEncoding.DecodeString(rawStr); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := hex.DecodeString(rawStr); err == nil && len(b) == 32 {
		return b, nil
	}
	if len(rawStr) == 32 {
		return []byte(rawStr), nil
	}
	return nil, fmt.Errorf("invalid key length %d: must decode to 32 bytes (base64, hex, or raw)", len(rawStr))
}

func setupBootstrapManager() (*transport.BootstrapManager, error) {
	if disableBootstrap {
		log.Println("[EMERGENCY-SERVER] Running in messaging-only mode (--disable-bootstrap); recovery candidate endpoint responses disabled")
		return transport.NewBootstrapManager(nil, "", 1)
	}

	var records []transport.BootstrapEndpointRecord

	if bootstrapConfigFile != "" {
		data, err := os.ReadFile(bootstrapConfigFile)
		if err != nil {
			return nil, fmt.Errorf("read bootstrap config file %s: %w", bootstrapConfigFile, err)
		}
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, fmt.Errorf("parse bootstrap config JSON in %s: %w (format must be valid JSON array of BootstrapEndpointRecord)", bootstrapConfigFile, err)
		}
		if len(records) == 0 {
			return nil, fmt.Errorf("bootstrap config file %s contains 0 candidate records (must contain at least one valid candidate)", bootstrapConfigFile)
		}
	} else {
		ip := bootstrapIP
		if ip == "" {
			ip = os.Getenv("PAQET_BOOTSTRAP_IP")
		}
		if ip == "" {
			return nil, errors.New("missing recovery endpoint configuration: a production emergency server must be supplied an explicit configuration via --bootstrap-config <file.json>, --bootstrap-ip <ip>, or explicitly pass --disable-bootstrap to run as a messaging-only emergency server (implicit defaults removed for fail-closed security)")
		}

		port := bootstrapPort
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid bootstrap port %d: must be between 1 and 65535", port)
		}

		mode := bootstrapMode
		if mode == "" {
			mode = "aead-stream"
		}

		var idType transport.EndpointIdentityType
		var idValue string
		var provenance string

		switch mode {
		case "tls-outer", "tls-stream":
			idType = transport.IdentityTypeCertPin
			if bootstrapCertFile != "" {
				fp, err := computeCertFingerprint(bootstrapCertFile)
				if err != nil {
					return nil, fmt.Errorf("tls bootstrap cert error: %w", err)
				}
				idValue = fp
				provenance = fmt.Sprintf("cert_file:%s", filepath.Base(bootstrapCertFile))
			} else if bootstrapPin != "" {
				idValue = bootstrapPin
				provenance = fmt.Sprintf("pin:%s", bootstrapPin[:min(14, len(bootstrapPin))]+"...[truncated]")
			} else {
				return nil, errors.New("tls-outer bootstrap requires an explicit certificate identity via --bootstrap-cert or --bootstrap-pin (cannot use shared PSK as TLS certificate fingerprint)")
			}

		case "aead-stream", "raw-kcp":
			idType = transport.IdentityTypePSKID
			if bootstrapKeyFile != "" {
				kData, err := os.ReadFile(bootstrapKeyFile)
				if err != nil {
					return nil, fmt.Errorf("read bootstrap key file %s: %w", bootstrapKeyFile, err)
				}
				kBytes, err := parseKeyBytes(string(kData))
				if err != nil {
					return nil, fmt.Errorf("parse bootstrap key in %s: %w", bootstrapKeyFile, err)
				}
				idValue = fmt.Sprintf("SHA256:%x", sha256.Sum256(kBytes))
				provenance = fmt.Sprintf("key_file:%s", filepath.Base(bootstrapKeyFile))
			} else if bootstrapPin != "" {
				idValue = bootstrapPin
				provenance = fmt.Sprintf("pin:%s", bootstrapPin[:min(14, len(bootstrapPin))]+"...[truncated]")
			} else {
				return nil, fmt.Errorf("%s bootstrap requires an explicit data-plane identity via --bootstrap-key-file or --bootstrap-pin (conflating recovery transport key with emergency PSK is strictly prohibited for security separation)", mode)
			}
		default:
			return nil, fmt.Errorf("unsupported bootstrap transport mode %q (fail-closed rejection)", mode)
		}

		records = append(records, transport.BootstrapEndpointRecord{
			ServerIP:      ip,
			TransportPort: port,
			TransportMode: mode,
			IdentityType:  idType,
			IdentityValue: idValue,
			Provenance:    provenance,
			ValiditySec:   7200,
		})
	}

	return transport.NewBootstrapManager(records, bootstrapMode, 1)
}

func validateServerStartupConfig(serverID, serverSecretFile string, legacyMode bool) ([]byte, error) {
	if !legacyMode {
		if serverID == "" {
			return nil, errors.New("emergency server: --server-id is mandatory for multi-authoritative emergency server (implicit defaults removed for fail-closed safety)")
		}
		if serverID == "default" || serverID == "legacy" {
			return nil, fmt.Errorf("emergency server: invalid server ID %q (cannot use default/legacy reserved ID)", serverID)
		}
		if err := transport.ValidateServerID(serverID); err != nil {
			return nil, fmt.Errorf("emergency server: invalid server ID %q: %w", serverID, err)
		}
		if serverSecretFile == "" {
			return nil, errors.New("emergency server: --server-secret-file is mandatory for multi-authoritative emergency server (shared PSK fallback prohibited)")
		}
		// Same deployment credential-file policy as the client loader: regular file
		// (no symlinks), no group/world access bits, exactly 32 decoded bytes.
		secret, err := loadProtectedCredentialFile(serverSecretFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load server secret file: %w", err)
		}
		return secret, nil
	}
	return nil, nil
}

// loadAuthorizedServersConfig parses and validates the explicit multi-server
// authorized-server mapping. Every failure mode is fail-closed BEFORE any network
// listener or credential is used. Secrets are never logged; only safe metadata
// (server IDs, generation, protocol) is returned.
func loadAuthorizedServersConfig(path string) ([]transport.AuthorizedServerEntry, string, uint64, error) {
	if path == "" {
		return nil, "", 0, errors.New("authorized-servers-config: empty path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", 0, fmt.Errorf("authorized-servers-config: read %s: %w", path, err)
	}
	var cfg AuthorizedServersConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, "", 0, fmt.Errorf("authorized-servers-config: parse %s: %w", path, err)
	}
	if cfg.Version != 1 {
		return nil, "", 0, fmt.Errorf("authorized-servers-config: unsupported schema version %d (want 1)", cfg.Version)
	}
	if cfg.Protocol != "v4" {
		return nil, "", 0, fmt.Errorf("authorized-servers-config: protocol %q not supported (must be explicit v4 multi-server)", cfg.Protocol)
	}
	if len(cfg.AuthorizedServers) == 0 {
		return nil, "", 0, errors.New("authorized-servers-config: authorized_servers list must be nonempty in multi-server mode")
	}
	seen := make(map[string]bool, len(cfg.AuthorizedServers))
	entries := make([]transport.AuthorizedServerEntry, 0, len(cfg.AuthorizedServers))
	for i, e := range cfg.AuthorizedServers {
		if e.ServerID == "" {
			return nil, "", 0, fmt.Errorf("authorized-servers-config: entry %d has empty server_id", i)
		}
		if e.ServerID == "default" || e.ServerID == "legacy" {
			return nil, "", 0, fmt.Errorf("authorized-servers-config: entry %d server_id %q is reserved", i, e.ServerID)
		}
		if err := transport.ValidateServerID(e.ServerID); err != nil {
			return nil, "", 0, fmt.Errorf("authorized-servers-config: entry %d server_id %q rejected: %w", i, e.ServerID, err)
		}
		if seen[e.ServerID] {
			return nil, "", 0, fmt.Errorf("authorized-servers-config: duplicate server_id %q (fail-closed: set replacement is atomic)", e.ServerID)
		}
		seen[e.ServerID] = true
		if e.SecretFile == "" {
			return nil, "", 0, fmt.Errorf("authorized-servers-config: entry %d (%s) has empty secret_file path (inline secrets prohibited)", i, e.ServerID)
		}
		secret, err := loadProtectedCredentialFile(e.SecretFile)
		if err != nil {
			return nil, "", 0, fmt.Errorf("authorized-servers-config: entry %d (%s): %w", i, e.ServerID, err)
		}
		entries = append(entries, transport.AuthorizedServerEntry{
			ServerID:       e.ServerID,
			ResponseSecret: append([]byte(nil), secret...), // deep copy from the file buffer
		})
	}
	return entries, cfg.Protocol, cfg.Generation, nil
}

// loadProtectedCredentialFile enforces the deployment credential-file policy:
// regular file only (symlinks rejected), no group/world access bits, decodable to
// exactly 32 bytes via the canonical key forms. Path and permission failures are
// reported without file contents.
func loadProtectedCredentialFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("lstat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("credential file %s is a symlink (rejected by deployment policy)", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("credential path %s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("credential file %s has unsafe permissions %o (must not be group/world accessible)", path, perm)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	secret, err := parseKeyBytes(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("credential file %s: %w", path, err)
	}
	if len(secret) != 32 {
		return nil, fmt.Errorf("credential file %s: decoded length %d (want 32)", path, len(secret))
	}
	return secret, nil
}

// resolveClientCredentialConfiguration applies the CLI flag ambiguity policy:
// CONFIG alone, LEGACY alone, or SINGULAR pair alone — never a mix — and returns
// the authorized entries plus the selected protocol mode.
func resolveClientCredentialConfiguration(cfgPath, singleID, singleSecret string, legacyMode bool) ([]transport.AuthorizedServerEntry, string, error) {
	singular := singleID != "" || singleSecret != ""
	switch {
	case legacyMode && cfgPath != "":
		return nil, "", errors.New("emergency client: --authorized-servers-config cannot be combined with --legacy-single-server (ambiguous mode selection)")
	case legacyMode && singular:
		return nil, "", errors.New("emergency client: --legacy-single-server cannot be combined with --server-id/--server-secret-file")
	case cfgPath != "" && singular:
		return nil, "", errors.New("emergency client: --authorized-servers-config is mutually exclusive with the singular --server-id/--server-secret-file convenience path")
	case legacyMode:
		return nil, "legacy", nil
	case cfgPath != "":
		entries, protocol, _, err := loadAuthorizedServersConfig(cfgPath)
		if err != nil {
			return nil, "", err
		}
		if len(entries) == 0 {
			return nil, "", errors.New("emergency client: resolved authorized set is empty (fail-closed)")
		}
		return entries, protocol, nil
	case singular:
		if singleID == "" || singleSecret == "" {
			return nil, "", errors.New("emergency client: multi-server operation requires both --server-id and --server-secret-file, or --authorized-servers-config")
		}
		entries, err := validateClientStartupConfig(singleID, singleSecret, false)
		if err != nil {
			return nil, "", err
		}
		return entries, "v3", nil
	default:
		return nil, "", errors.New("emergency client: no server authorization configuration supplied (provide --authorized-servers-config, or --legacy-single-server)")
	}
}

func validateClientStartupConfig(serverID, serverSecretFile string, legacyMode bool) ([]transport.AuthorizedServerEntry, error) {
	if !legacyMode {
		if serverID == "" {
			return nil, errors.New("emergency client: --server-id is mandatory for multi-authoritative client")
		}
		if serverSecretFile == "" {
			return nil, errors.New("emergency client: --server-secret-file is mandatory for multi-authoritative client (shared PSK fallback prohibited)")
		}
		secret, err := parseKey("", serverSecretFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load server secret file %q: %w", serverSecretFile, err)
		}
		if len(secret) != 32 {
			return nil, fmt.Errorf("emergency client: server secret in %q must be exactly 32 bytes, got %d", serverSecretFile, len(secret))
		}
		return []transport.AuthorizedServerEntry{{ServerID: serverID, ResponseSecret: secret}}, nil
	}
	return nil, nil
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Runs the authoritative emergency DNS daemon",
	Run: func(cmd *cobra.Command, args []string) {
		psk, err := parseKey(keyStr, keyFile)
		if err != nil {
			log.Fatalf("failed to load emergency key: %v", err)
		}

		serverSecret, err := validateServerStartupConfig(serverID, serverSecretFile, legacySingleServer)
		if err != nil {
			log.Fatalf("failed startup: %v", err)
		}
		if legacySingleServer {
			log.Println("[EMERGENCY-SERVER] Running in legacy single-server mode (--legacy-single-server); multi-authoritative security guarantees are disabled")
			if serverID == "" {
				serverID = "legacy"
			}
		}

		bm, err := setupBootstrapManager()
		if err != nil {
			log.Fatalf("failed to initialize bootstrap manager: %v", err)
		}
		bm.SetAuthoritativeServerID(serverID)

		srv, err := transport.NewEmergencyDNSServer(transport.EmergencyDNSServerConfig{
			ListenAddr:           listenAddr,
			DomainSuffix:         domainSuffix,
			PSK:                  psk,
			ServerID:             serverID,
			ServerSecret:         serverSecret,
			IsLegacySingleServer: legacySingleServer,
			ProtocolV4:           protocolV4,
			Handler: func(msg *transport.EmergencyMessage) (*transport.EmergencyResponse, error) {
				// Privacy and Security: Log only metadata, never plaintext payload or key material
				log.Printf("[EMERGENCY-SERVER] Authenticated message ID=%s Type=%s PayloadBytes=%d ClientID=%s Status=PROCESSED",
					msg.ID, msg.Type, len(msg.Payload), clientID)

				if msg.Type == "bootstrap_request" {
					requestedMode := strings.TrimSpace(string(msg.Payload))
					if requestedMode == "" || requestedMode == "REQUEST_BOOTSTRAP_ENDPOINT" {
						requestedMode = bootstrapMode
					}
					endpointData, err := bm.GenerateResponse(msg, requestedMode)
					if err != nil {
						return &transport.EmergencyResponse{
							ID:        msg.ID,
							Status:    "ERROR",
							Reply:     []byte(err.Error()),
							Timestamp: time.Now().Unix(),
						}, nil
					}
					payload, err := json.Marshal(endpointData)
					if err == nil {
						log.Printf("[EMERGENCY-SERVER] Generated bootstrap response ID=%s Mode=%s Endpoint=%s:%d IdentityType=%s",
							msg.ID, endpointData.TransportMode, endpointData.ServerIP, endpointData.TransportPort, endpointData.IdentityType)
						return &transport.EmergencyResponse{
							ID:        msg.ID,
							Status:    "OK",
							Reply:     payload,
							Timestamp: time.Now().Unix(),
						}, nil
					}
				}

				return &transport.EmergencyResponse{
					ID:        msg.ID,
					Status:    "OK",
					Reply:     append([]byte("ACK_ECHO:"), msg.Payload...),
					Timestamp: time.Now().Unix(),
				}, nil
			},
		})
		if err != nil {
			log.Fatalf("failed to start emergency dns server: %v", err)
		}
		defer srv.Stop()

		log.Printf("[EMERGENCY-SERVER] Listening on %s (UDP+TCP) for domain *.%s", srv.Addr(), domainSuffix)

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("[EMERGENCY-SERVER] Shutting down...")
	},
}

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Transmits an authenticated emergency message over recursive DNS and waits for reply",
	Run: func(cmd *cobra.Command, args []string) {
		psk, err := parseKey(keyStr, keyFile)
		if err != nil {
			log.Fatalf("failed to load emergency key: %v", err)
		}

		clientEntries, protocolMode, err := resolveClientCredentialConfiguration(authorizedServersCfg, serverID, serverSecretFile, legacySingleServer)
		if err != nil {
			log.Fatalf("failed startup: %v", err)
		}

		var clientCfg transport.EmergencyDNSClientConfig
		switch protocolMode {
		case "legacy":
			clientCfg = transport.EmergencyDNSClientConfig{
				ResolverAddr:         resolverAddr,
				DomainSuffix:         domainSuffix,
				ClientID:             clientID,
				PSK:                  psk,
				Timeout:              time.Duration(timeoutSec) * time.Second,
				MaxRetries:           2,
				IsLegacySingleServer: true,
			}
		case "v4":
			clientCfg = transport.EmergencyDNSClientConfig{
				ResolverAddr:     resolverAddr,
				DomainSuffix:     domainSuffix,
				ClientID:         clientID,
				PSK:              psk,
				Timeout:          time.Duration(timeoutSec) * time.Second,
				MaxRetries:       2,
				ProtocolV4:       true,
				ServerIdentities: clientEntries,
			}
		default: // "v3"
			clientCfg = transport.EmergencyDNSClientConfig{
				ResolverAddr:     resolverAddr,
				DomainSuffix:     domainSuffix,
				ClientID:         clientID,
				PSK:              psk,
				Timeout:          time.Duration(timeoutSec) * time.Second,
				MaxRetries:       2,
				ServerIdentities: clientEntries,
			}
		}

		client, err := transport.NewEmergencyDNSClient(clientCfg)
		if err != nil {
			log.Fatalf("failed to initialize emergency client: %v", err)
		}
		// Safe, credential-free metadata: active protocol version + authorized server IDs.
		fmt.Printf("[CLIENT] protocol=%s authorized-servers=%v\n", client.ProtocolVersionName(), client.AuthorizedServerIDs())

		msgID := transport.GenerateRandomMessageID()
		msg := &transport.EmergencyMessage{
			ID:        msgID,
			Type:      "alert",
			Payload:   []byte(messageStr),
			Timestamp: time.Now().Unix(),
		}

		fmt.Printf("[CLIENT] Sending emergency message ID=%s (%d bytes) to %s via *.%s...\n",
			msgID, len(msg.Payload), resolverAddr, domainSuffix)
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+2)*time.Second)
		defer cancel()

		resp, rtt, err := client.Exchange(ctx, msg)
		if err != nil {
			log.Fatalf("[CLIENT] Exchange failed: %v", err)
		}

		fmt.Printf("[CLIENT] SUCCESS! RTT: %v\n", rtt)
		fmt.Printf(" - Response ID: %s\n", resp.ID)
		fmt.Printf(" - Status:      %s\n", resp.Status)
		fmt.Printf(" - Reply Bytes: %d\n", len(resp.Reply))
		if len(resp.Reply) <= 256 {
			fmt.Printf(" - Reply Echo:  %s\n", string(resp.Reply))
		} else {
			fmt.Printf(" - Reply Echo:  %s... (truncated preview)\n", string(resp.Reply[:64]))
		}
	},
}

func parseKey(kStr, kFile string) ([]byte, error) {
	var rawStr string

	if kFile != "" {
		data, err := os.ReadFile(kFile)
		if err != nil {
			return nil, fmt.Errorf("read key file %s: %w", kFile, err)
		}
		rawStr = strings.TrimSpace(string(data))
	} else if credDir := os.Getenv("CREDENTIALS_DIRECTORY"); credDir != "" {
		credPath := filepath.Join(credDir, "emergency_key")
		if data, err := os.ReadFile(credPath); err == nil {
			rawStr = strings.TrimSpace(string(data))
		}
	}

	if rawStr == "" {
		if envKey := os.Getenv("PAQET_EMERGENCY_KEY"); envKey != "" {
			rawStr = strings.TrimSpace(envKey)
		}
	}

	if rawStr == "" && kStr != "" {
		rawStr = strings.TrimSpace(kStr)
	}

	if rawStr == "" {
		return nil, errors.New("no emergency key provided. An explicit 32-byte key must be supplied via --key-file, $PAQET_EMERGENCY_KEY, or --key")
	}

	return parseKeyBytes(rawStr)
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Evaluates candidate recursive DNS resolvers for emergency tunnel capability",
	Run: func(cmd *cobra.Command, args []string) {
		var candidates []string
		if scanResolvers != "" {
			for _, r := range strings.Split(scanResolvers, ",") {
				r = strings.TrimSpace(r)
				if r != "" {
					candidates = append(candidates, r)
				}
			}
		} else {
			candidates = append(dns.GetSystemResolvers(), dns.DefaultPublicResolvers()...)
		}

		// Deduplicate candidates
		seen := make(map[string]bool)
		var unique []string
		for _, c := range candidates {
			if !seen[c] {
				seen[c] = true
				unique = append(unique, c)
			}
		}

		fmt.Printf("[SCANNER] Evaluating %d candidate resolvers against *.%s (timeout=%ds)...\n\n",
			len(unique), domainSuffix, timeoutSec)

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec*4)*time.Second)
		defer cancel()

		results := dns.ScanResolverPool(ctx, unique, 53, domainSuffix, time.Duration(timeoutSec)*time.Second, 4)

		fmt.Printf("%-18s %-8s %-18s %-6s %-10s %-8s %-8s %-10s\n",
			"RESOLVER", "STATUS", "PROFILE", "SCORE", "LATENCY", "EDNS0", "NXDOMAIN", "CAPABILITY")
		fmt.Println(strings.Repeat("-", 97))

		for _, r := range results {
			nxStatus := "HIJACKED"
			if r.NXDOMAINPreserved {
				nxStatus = "CLEAN"
			}
			ednsStr := fmt.Sprintf("%dB", r.EDNS0MaxPayload)
			if !r.EDNS0Support {
				ednsStr = "NONE"
			}
			capabilityStr := "FAIL"
			if r.SupportsLongLabels && r.SupportsTXT {
				capabilityStr = "PASS"
			}

			fmt.Printf("%-18s %-8s %-18s %d/6    %-10s %-8s %-8s %-10s\n",
				r.Host, r.Status, r.Profile, r.Score,
				fmt.Sprintf("%.1fms", float64(r.Latency.Microseconds())/1000.0),
				ednsStr, nxStatus, capabilityStr)
		}

		fmt.Println("\nNote: 'CAPABILITY PASS' verifies DNS protocol, long label, and TXT capability.")
		fmt.Println("      It does NOT guarantee end-to-end transport without an authenticated payload exchange.")

		if len(results) > 0 && results[0].Score >= 4 && results[0].NXDOMAINPreserved {
			fmt.Printf("\n[RECOMMENDATION] Optimal candidate resolver: %s:53 (Score %d/6, Latency %v)\n",
				results[0].Host, results[0].Score, results[0].Latency)
		} else {
			fmt.Println("\n[WARNING] No candidate passed all censorship checks with clean NXDOMAIN preservation.")
		}

		if scanCacheFile != "" {
			if err := dns.SaveResolverCache(scanCacheFile, results); err == nil {
				fmt.Printf("[CACHE] Saved results to %s\n", scanCacheFile)
			}
		}
	},
}
