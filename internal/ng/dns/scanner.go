package dns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DNS Record Types (RFC 1035, RFC 6891)
const (
	TypeA   uint16 = 1
	TypeNS  uint16 = 2
	TypeTXT uint16 = 16
	TypeOPT uint16 = 41 // EDNS0 pseudo-RR
)

// ResolverStatus classifications
type ResolverStatus string

const (
	StatusWorking  ResolverStatus = "WORKING"
	StatusTimeout  ResolverStatus = "TIMEOUT"
	StatusHijacked ResolverStatus = "HIJACKED"
	StatusError    ResolverStatus = "ERROR"
)

// ResolverProfile categorizes resolver origin and trust level.
type ResolverProfile string

const (
	ProfilePreconfigured    ResolverProfile = "PRECONFIGURED"
	ProfileDiscovered       ResolverProfile = "DISCOVERED"
	ProfileTunnelCompatible ResolverProfile = "TUNNEL_COMPATIBLE"
	ProfileBlocked          ResolverProfile = "BLOCKED"
)

// ResolverCapabilities reports detailed protocol capabilities and censorship behaviors of a resolver.
type ResolverCapabilities struct {
	Host               string
	Port               int
	Profile            ResolverProfile
	Status             ResolverStatus
	Latency            time.Duration
	SupportsNS         bool
	SupportsTXT        bool
	SupportsRandomSub  bool
	SupportsLongLabels bool // Tunnel realism check (Base32 labels up to 57 chars)
	EDNS0Support       bool
	EDNS0MaxPayload    int  // Measured maximum buffer size (e.g. 512, 1232, 1400)
	NXDOMAINPreserved  bool // True if resolver preserves RFC 1035 RCODE=3; False if hijacked by ISP
	Score              int  // Composite score: 0 (unusable) to 6 (optimal)
	LastError          string
	LastTested         time.Time
}

// ComputeScore evaluates the composite score (0..6) of the resolver.
func (c *ResolverCapabilities) ComputeScore() int {
	score := 0
	if c.Status != StatusWorking {
		c.Score = 0
		return 0
	}
	if c.SupportsNS {
		score++
	}
	if c.SupportsTXT {
		score++
	}
	if c.SupportsRandomSub {
		score++
	}
	if c.SupportsLongLabels {
		score++
	}
	if c.EDNS0Support && c.EDNS0MaxPayload >= 512 {
		score++
	}
	if c.NXDOMAINPreserved {
		score++
	}
	c.Score = score
	if score >= 4 && c.NXDOMAINPreserved {
		c.Profile = ProfileTunnelCompatible
	} else {
		c.Profile = ProfileBlocked
	}
	return score
}

// BuildQueryPacket constructs an authentic RFC 1035 DNS query packet with optional RFC 6891 EDNS0 OPT RR.
func BuildQueryPacket(qname string, qtype uint16, id uint16, edns0Payload uint16) []byte {
	var buf []byte

	// 12-byte DNS Header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // RD = 1 (Recursion Desired)
	binary.BigEndian.PutUint16(header[4:6], 1)      // QDCOUNT = 1
	if edns0Payload > 0 {
		binary.BigEndian.PutUint16(header[10:12], 1) // ARCOUNT = 1 (OPT RR in Additional)
	}
	buf = append(buf, header...)

	// QNAME
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	for _, l := range labels {
		if len(l) == 0 {
			continue
		}
		if len(l) > 63 {
			l = l[:63]
		}
		buf = append(buf, byte(len(l)))
		buf = append(buf, l...)
	}
	buf = append(buf, 0x00) // Root label

	// QTYPE & QCLASS
	trailer := make([]byte, 4)
	binary.BigEndian.PutUint16(trailer[0:2], qtype)
	binary.BigEndian.PutUint16(trailer[2:4], 0x0001) // Class IN
	buf = append(buf, trailer...)

	// EDNS0 OPT Pseudo-RR (RFC 6891) in Additional Section
	if edns0Payload > 0 {
		opt := make([]byte, 11)
		opt[0] = 0x00 // Root domain name
		binary.BigEndian.PutUint16(opt[1:3], TypeOPT)
		binary.BigEndian.PutUint16(opt[3:5], edns0Payload) // Requestor's UDP payload size
		opt[5] = 0x00                                      // Extended RCODE
		opt[6] = 0x00                                      // EDNS version 0
		binary.BigEndian.PutUint16(opt[7:9], 0x0000)       // Z flags (DO=0)
		binary.BigEndian.PutUint16(opt[9:11], 0x0000)      // RDLEN = 0
		buf = append(buf, opt...)
	}

	return buf
}

// SendQuery transmits a DNS query to a target resolver over UDP with timeout.
func SendQuery(ctx context.Context, host string, port int, qname string, qtype uint16, edns0Payload uint16, timeout time.Duration) ([]byte, time.Duration, error) {
	if port <= 0 {
		port = 53
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	nBig, _ := rand.Int(rand.Reader, big.NewInt(65535))
	txID := uint16(nBig.Int64())

	packet := BuildQueryPacket(qname, qtype, txID, edns0Payload)

	start := time.Now()
	if _, err := conn.Write(packet); err != nil {
		return nil, 0, err
	}

	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	rtt := time.Since(start)
	if err != nil {
		return nil, rtt, err
	}

	if n < 12 {
		return nil, rtt, errors.New("dns: response too short")
	}

	return respBuf[:n], rtt, nil
}

// ScanResolver independently tests a resolver across all capability metrics.
func ScanResolver(ctx context.Context, host string, port int, testDomain string, timeout time.Duration) ResolverCapabilities {
	if port <= 0 {
		port = 53
	}
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}

	res := ResolverCapabilities{
		Host:       host,
		Port:       port,
		Profile:    ProfileDiscovered,
		Status:     StatusWorking,
		LastTested: time.Now(),
	}

	// 1. Basic A Reachability & RTT
	probeQuery := "example.com"
	resp, rtt, err := SendQuery(ctx, host, port, probeQuery, TypeA, 0, timeout)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
			res.Status = StatusTimeout
		} else {
			res.Status = StatusError
		}
		res.LastError = err.Error()
		res.ComputeScore()
		return res
	}

	res.Latency = rtt
	rcode := int(resp[3] & 0x0F)
	if rcode != 0 && rcode != 3 { // Must not be Server Failure (2) or Format Error (1)
		res.Status = StatusError
		res.LastError = fmt.Sprintf("resolver returned rcode %d on basic probe", rcode)
		res.ComputeScore()
		return res
	}

	// Run detailed capability tests concurrently
	var wg sync.WaitGroup
	wg.Add(5)

	// Check 2: NS Query Support
	go func() {
		defer wg.Done()
		r, _, err := SendQuery(ctx, host, port, "com", TypeNS, 0, timeout)
		if err == nil && len(r) >= 12 && (r[3]&0x0F) == 0 {
			ancount := binary.BigEndian.Uint16(r[6:8])
			nscount := binary.BigEndian.Uint16(r[8:10])
			if ancount > 0 || nscount > 0 {
				res.SupportsNS = true
			}
		}
	}()

	// Check 3: TXT Query Support
	go func() {
		defer wg.Done()
		r, _, err := SendQuery(ctx, host, port, "google.com", TypeTXT, 0, timeout)
		if err == nil && len(r) >= 12 && (r[3]&0x0F) == 0 {
			res.SupportsTXT = true
		}
	}()

	// Check 4: Dynamic Subdomain Support
	go func() {
		defer wg.Done()
		randStr := randomLabel(10)
		target := fmt.Sprintf("%s.cloudflare.com", randStr)
		r, _, err := SendQuery(ctx, host, port, target, TypeA, 0, timeout)
		if err == nil && len(r) >= 12 {
			res.SupportsRandomSub = true
		}
	}()

	// Check 5: Tunnel Realism (Long Base32 Labels)
	go func() {
		defer wg.Done()
		longLabel := strings.ToLower("mzxw6ytb1234567890abcdefghijklmnopqrstuvwxyzmzxw6ytb1234") // 56 chars
		domain := testDomain
		if domain == "" {
			domain = "example.com"
		}
		target := fmt.Sprintf("%s.%s", longLabel, domain)
		r, _, err := SendQuery(ctx, host, port, target, TypeA, 0, timeout)
		if err == nil && len(r) >= 12 {
			res.SupportsLongLabels = true
		}
	}()

	// Check 6: NXDOMAIN Non-Hijack Check
	go func() {
		defer wg.Done()
		bogusDomain := fmt.Sprintf("%s.invalid", randomLabel(12))
		r, _, err := SendQuery(ctx, host, port, bogusDomain, TypeA, 0, timeout)
		if err == nil && len(r) >= 12 {
			bogusRcode := int(r[3] & 0x0F)
			ancount := binary.BigEndian.Uint16(r[6:8])
			if bogusRcode == 3 && ancount == 0 {
				res.NXDOMAINPreserved = true
			} else {
				// Resolver returned an IP or NOERROR for .invalid! Hijacked by censor/ISP.
				res.NXDOMAINPreserved = false
			}
		}
	}()

	wg.Wait()

	// Check 7: EDNS0 Payload Capacity (Sequential probe: 512, 1232, 1400)
	payloadSizes := []uint16{512, 1232, 1400}
	for _, size := range payloadSizes {
		r, _, err := SendQuery(ctx, host, port, "example.com", TypeA, size, timeout)
		if err == nil && len(r) >= 12 && (r[3]&0x0F) == 0 {
			arcount := binary.BigEndian.Uint16(r[10:12])
			if arcount > 0 {
				res.EDNS0Support = true
				res.EDNS0MaxPayload = int(size)
			}
		}
	}

	res.ComputeScore()
	return res
}

// ScanResolverPool concurrently evaluates candidate resolvers with bounded concurrency.
func ScanResolverPool(ctx context.Context, hosts []string, port int, testDomain string, timeout time.Duration, concurrency int) []ResolverCapabilities {
	if concurrency <= 0 {
		concurrency = 8
	}
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var results []ResolverCapabilities

	var wg sync.WaitGroup
	for _, h := range hosts {
		h := strings.TrimSpace(h)
		if h == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(entry string) {
			defer wg.Done()
			defer func() { <-sem }()
			targetHost := entry
			targetPort := port
			if h, pStr, err := net.SplitHostPort(entry); err == nil {
				targetHost = h
				if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
					targetPort = p
				}
			}
			cap := ScanResolver(ctx, targetHost, targetPort, testDomain, timeout)
			mu.Lock()
			results = append(results, cap)
			mu.Unlock()
		}(h)
	}

	wg.Wait()

	// Sort results: highest Score first, then lowest Latency
	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		return results[i].Latency < results[j].Latency
	})

	return results
}

// DefaultPublicResolvers returns a curated set of resilient public recursive DNS resolvers.
func DefaultPublicResolvers() []string {
	return []string{
		"8.8.8.8", // Google Primary
		"1.1.1.1", // Cloudflare Primary
		"9.9.9.9", // Quad9 Primary
		"8.8.4.4", // Google Secondary
		"1.0.0.1", // Cloudflare Secondary
		"4.2.2.4", // Level3 / CenturyLink
	}
}

// GetSystemResolvers parses /etc/resolv.conf on Linux/Unix environments to discover local resolvers.
func GetSystemResolvers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var resolvers []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip := net.ParseIP(parts[1])
				// Include valid IPv4 resolvers (and IPv6 if desired)
				if ip != nil && ip.To4() != nil {
					resolvers = append(resolvers, parts[1])
				}
			}
		}
	}
	return resolvers
}

// SaveResolverCache persists scanned resolver capabilities to a JSON file.
func SaveResolverCache(path string, results []ResolverCapabilities) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadResolverCache loads previously cached resolver profiles if they are newer than maxAge.
func LoadResolverCache(path string, maxAge time.Duration) ([]ResolverCapabilities, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var results []ResolverCapabilities
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}
	if maxAge > 0 {
		var fresh []ResolverCapabilities
		now := time.Now()
		for _, r := range results {
			if now.Sub(r.LastTested) <= maxAge {
				fresh = append(fresh, r)
			}
		}
		return fresh, nil
	}
	return results, nil
}

func randomLabel(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}
