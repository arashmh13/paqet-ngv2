package transport

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arashmh13/paqet-ngv2/internal/ng/dns"
)

var (
	ErrDNSInvalidQuery    = errors.New("dns-asymmetric: invalid qname framing")
	ErrDNSFrameIncomplete = errors.New("dns-asymmetric: frame assembly incomplete")
)

var b32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeDNSQName encodes payload chunks into RFC 1035 compliant domain labels.
// Format: p<part>.t<total>.o<offset>.<base32chunk>.<clientID>.<domainSuffix>
func EncodeDNSQName(domainSuffix, clientID string, offset uint64, part, total uint8, chunk []byte) string {
	encodedData := strings.ToLower(b32Encoding.EncodeToString(chunk))
	// Ensure labels are <= 63 characters
	return fmt.Sprintf("p%d.t%d.o%d.%s.%s.%s", part, total, offset, encodedData, clientID, domainSuffix)
}

// DecodeDNSQName parses and decodes an incoming DNS QNAME into its constituent metadata and payload.
func DecodeDNSQName(qname, domainSuffix string) (clientID string, offset uint64, part, total uint8, data []byte, err error) {
	qname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	domainSuffix = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domainSuffix)), ".")

	if !strings.HasSuffix(qname, "."+domainSuffix) {
		return "", 0, 0, 0, nil, ErrDNSInvalidQuery
	}

	prefix := strings.TrimSuffix(qname, "."+domainSuffix)
	labels := strings.Split(prefix, ".")
	if len(labels) < 5 {
		return "", 0, 0, 0, nil, ErrDNSInvalidQuery
	}

	// label 0: p<part>
	if len(labels[0]) < 2 || labels[0][0] != 'p' {
		return "", 0, 0, 0, nil, ErrDNSInvalidQuery
	}
	pInt, err := strconv.Atoi(labels[0][1:])
	if err != nil {
		return "", 0, 0, 0, nil, err
	}
	part = uint8(pInt)

	// label 1: t<total>
	if len(labels[1]) < 2 || labels[1][0] != 't' {
		return "", 0, 0, 0, nil, ErrDNSInvalidQuery
	}
	tInt, err := strconv.Atoi(labels[1][1:])
	if err != nil {
		return "", 0, 0, 0, nil, err
	}
	total = uint8(tInt)
	if total == 0 || total > 64 || part >= total {
		return "", 0, 0, 0, nil, ErrDNSInvalidQuery
	}

	// label 2: o<offset>
	if len(labels[2]) < 2 || labels[2][0] != 'o' {
		return "", 0, 0, 0, nil, ErrDNSInvalidQuery
	}
	oInt, err := strconv.ParseUint(labels[2][1:], 10, 64)
	if err != nil {
		return "", 0, 0, 0, nil, err
	}
	offset = oInt

	// label 3: base32 payload
	b32Data := strings.ToUpper(labels[3])
	data, err = b32Encoding.DecodeString(b32Data)
	if err != nil {
		return "", 0, 0, 0, nil, fmt.Errorf("base32 decode: %w", err)
	}

	// label 4: clientID
	clientID = labels[4]

	return clientID, offset, part, total, data, nil
}

// frameAssembly tracks multipart fragments for a single logical datagram.
type frameAssembly struct {
	totalParts uint8
	parts      map[uint8][]byte
	createdAt  time.Time
}

// DNSReassembler collects out-of-order fragments arriving via DNS queries.
type DNSReassembler struct {
	mu      sync.Mutex
	frames  map[string]*frameAssembly
	timeout time.Duration
}

func NewDNSReassembler(timeout time.Duration) *DNSReassembler {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	r := &DNSReassembler{
		frames:  make(map[string]*frameAssembly),
		timeout: timeout,
	}
	go r.cleanerLoop()
	return r
}

func (r *DNSReassembler) cleanerLoop() {
	ticker := time.NewTicker(r.timeout / 2)
	defer ticker.Stop()
	for range ticker.C {
		r.mu.Lock()
		now := time.Now()
		for key, f := range r.frames {
			if now.Sub(f.createdAt) > r.timeout {
				delete(r.frames, key)
			}
		}
		r.mu.Unlock()
	}
}

// MaxPendingFrames limits pending reassembly sessions to prevent RAM exhaustion.
const MaxPendingFrames = 1024

// PushFragment inserts a fragment. If this completes the frame, it returns the full byte slice.
func (r *DNSReassembler) PushFragment(clientID string, offset uint64, part, total uint8, chunk []byte) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%d", clientID, offset)
	fa, exists := r.frames[key]
	if !exists {
		if len(r.frames) >= MaxPendingFrames {
			return nil, false // Protect memory against fragment flood attacks
		}
		fa = &frameAssembly{
			totalParts: total,
			parts:      make(map[uint8][]byte),
			createdAt:  time.Now(),
		}
		r.frames[key] = fa
	}

	fa.parts[part] = append([]byte(nil), chunk...)

	if len(fa.parts) == int(fa.totalParts) {
		// All fragments present; reassemble in order
		var full []byte
		for i := uint8(0); i < fa.totalParts; i++ {
			p, ok := fa.parts[i]
			if !ok {
				return nil, false
			}
			full = append(full, p...)
		}
		delete(r.frames, key)
		return full, true
	}

	return nil, false
}

// DNSAsymmetricConfig holds configuration for the DNS asymmetric transport.
type DNSAsymmetricConfig struct {
	ResolverAddr string   // Primary resolver (e.g. "8.8.8.8:53")
	ResolverPool []string // Optional candidate pool for dynamic resolver discovery & scoring
	DomainSuffix string   // e.g. "tunnel.example.com"
	ClientID     string
	PSK          []byte
}

// DNSAsymmetricDialer implements the Strategy interface for DNS-asymmetric transport.
type DNSAsymmetricDialer struct {
	cfg       DNSAsymmetricConfig
	metrics   HealthMetrics
	metricsMu sync.RWMutex
}

func NewDNSAsymmetricDialer(cfg DNSAsymmetricConfig) *DNSAsymmetricDialer {
	if cfg.ResolverAddr == "" {
		cfg.ResolverAddr = "8.8.8.8:53"
	}
	if cfg.DomainSuffix == "" {
		cfg.DomainSuffix = "tunnel.example.com"
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "c01"
	}
	return &DNSAsymmetricDialer{
		cfg: cfg,
		metrics: HealthMetrics{
			Mode:         ModeDNSAsymmetric,
			Available:    true,
			CircuitState: "closed",
		},
	}
}

// SelectBestResolver probes the candidate resolver pool using clean-room multi-factor scoring
// and selects the highest-scoring, lowest-latency unpoisoned resolver.
func (d *DNSAsymmetricDialer) SelectBestResolver(ctx context.Context) string {
	d.metricsMu.RLock()
	pool := make([]string, len(d.cfg.ResolverPool))
	copy(pool, d.cfg.ResolverPool)
	current := d.cfg.ResolverAddr
	suffix := d.cfg.DomainSuffix
	d.metricsMu.RUnlock()

	if len(pool) == 0 {
		return current
	}

	results := dns.ScanResolverPool(ctx, pool, 53, suffix, 2*time.Second, 4)
	if len(results) > 0 && results[0].Score >= 4 {
		best := net.JoinHostPort(results[0].Host, fmt.Sprintf("%d", results[0].Port))
		d.metricsMu.Lock()
		d.cfg.ResolverAddr = best
		d.metricsMu.Unlock()
		return best
	}

	return current
}

func (d *DNSAsymmetricDialer) Mode() TransportMode {
	return ModeDNSAsymmetric
}

func (d *DNSAsymmetricDialer) Capabilities() TransportCapabilities {
	return TransportCapabilities{
		Mode:               ModeDNSAsymmetric,
		RequiresRoot:       false,
		SupportsNAT:        true,
		MaxThroughputMbps:  0.8,
		ExpectedLatencyMs:  650,
		IsAsymmetric:       true,
		PrerequisitesMet:   true,
		PrerequisiteNotice: "Upstream carries Base32 chunks over DNS UDP:53; low-throughput emergency survival channel",
	}
}

func (d *DNSAsymmetricDialer) Dial(ctx context.Context, addr string) (Session, error) {
	// DNS-asymmetric operates as a packet-forwarding emergency channel.
	// We simulate dial and establish metrics
	start := time.Now()
	rtt, err := d.CheckHealth(ctx, addr)
	if err != nil {
		d.recordMetric(false, time.Since(start), err)
		return nil, fmt.Errorf("dns-asymmetric dial: %w", err)
	}
	d.recordMetric(true, rtt, nil)
	return nil, errors.New("dns-asymmetric: session established as UDP datagram forwarder (use datagram channel)")
}

func (d *DNSAsymmetricDialer) CheckHealth(ctx context.Context, addr string) (time.Duration, error) {
	start := time.Now()
	// Test DNS resolver reachability on UDP:53
	conn, err := net.DialTimeout("udp", d.cfg.ResolverAddr, 2*time.Second)
	if err != nil {
		d.recordMetric(false, time.Since(start), err)
		return 0, err
	}
	_ = conn.Close()
	rtt := time.Since(start)
	d.recordMetric(true, rtt, nil)
	return rtt, nil
}

func (d *DNSAsymmetricDialer) recordMetric(success bool, rtt time.Duration, err error) {
	d.metricsMu.Lock()
	defer d.metricsMu.Unlock()

	d.metrics.TotalAttempts++
	d.metrics.LastAttemptTime = time.Now()

	if success {
		d.metrics.TotalSuccesses++
		d.metrics.FailureStreak = 0
		d.metrics.CircuitState = "closed"
		d.metrics.Available = true
		d.metrics.LastSuccessTime = time.Now()
		if d.metrics.LatencyEMA == 0 {
			d.metrics.LatencyEMA = rtt
		} else {
			d.metrics.LatencyEMA = time.Duration(0.8*float64(d.metrics.LatencyEMA) + 0.2*float64(rtt))
		}
	} else {
		d.metrics.FailureStreak++
		if err != nil {
			d.metrics.LastErrorReason = err.Error()
		}
		if d.metrics.FailureStreak >= 3 {
			d.metrics.CircuitState = "open"
			d.metrics.Available = false
		}
	}

	if d.metrics.TotalAttempts > 0 {
		d.metrics.SuccessRate = float64(d.metrics.TotalSuccesses) / float64(d.metrics.TotalAttempts)
	}
}

func (d *DNSAsymmetricDialer) Metrics() HealthMetrics {
	d.metricsMu.RLock()
	defer d.metricsMu.RUnlock()
	return d.metrics
}

const (
	// DefaultEDNSUDPPayloadSize is the DNS Flag Day recommended conservative buffer size (1232 bytes)
	// that guarantees UDP datagrams avoid IPv4/IPv6 fragmentation across all standard MTUs.
	DefaultEDNSUDPPayloadSize uint16 = 1232
	// MaxSafeDNSUDPPayloadSize is the maximum safe UDP DNS packet size before forcing TCP truncation (1400 bytes).
	MaxSafeDNSUDPPayloadSize = 1400
)

// skipDomainName advances past a DNS domain name in wire format (handling labels and compression pointers).
func skipDomainName(packet []byte, offset int) (int, error) {
	for offset < len(packet) {
		b := packet[offset]
		if b == 0 {
			return offset + 1, nil
		}
		if b&0xC0 == 0xC0 { // Compression pointer (2 bytes)
			if offset+2 > len(packet) {
				return 0, errors.New("truncated pointer")
			}
			return offset + 2, nil
		}
		offset += 1 + int(b)
	}
	return 0, errors.New("unterminated domain name")
}

// skipResourceRecord advances past a full Resource Record in wire format.
func skipResourceRecord(packet []byte, offset int) (int, error) {
	newOffset, err := skipDomainName(packet, offset)
	if err != nil {
		return 0, err
	}
	// TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes
	if newOffset+10 > len(packet) {
		return 0, errors.New("truncated RR header")
	}
	rdlen := int(binary.BigEndian.Uint16(packet[newOffset+8 : newOffset+10]))
	newOffset += 10 + rdlen
	if newOffset > len(packet) {
		return 0, errors.New("truncated RDATA")
	}
	return newOffset, nil
}

// ParseEDNSOption extracts the client's advertised UDP buffer size and presence of an RFC 6891 OPT record
// from the Additional section of an incoming wire DNS packet.
func ParseEDNSOption(packet []byte) (hasOPT bool, bufSize uint16, err error) {
	if len(packet) < 12 {
		return false, 512, ErrDNSInvalidQuery
	}
	qdcount := binary.BigEndian.Uint16(packet[4:6])
	ancount := binary.BigEndian.Uint16(packet[6:8])
	nscount := binary.BigEndian.Uint16(packet[8:10])
	arcount := binary.BigEndian.Uint16(packet[10:12])

	if arcount == 0 {
		return false, 512, nil
	}

	offset := 12
	// Walk Question section
	for i := 0; i < int(qdcount); i++ {
		offset, err = skipDomainName(packet, offset)
		if err != nil {
			return false, 512, err
		}
		offset += 4 // QTYPE + QCLASS
		if offset > len(packet) {
			return false, 512, errors.New("truncated question section")
		}
	}

	// Walk Answer section
	for i := 0; i < int(ancount); i++ {
		offset, err = skipResourceRecord(packet, offset)
		if err != nil {
			return false, 512, err
		}
	}

	// Walk Authority section
	for i := 0; i < int(nscount); i++ {
		offset, err = skipResourceRecord(packet, offset)
		if err != nil {
			return false, 512, err
		}
	}

	// Walk Additional section
	for i := 0; i < int(arcount); i++ {
		nameOffset := offset
		newOffset, err := skipDomainName(packet, offset)
		if err != nil {
			return false, 512, err
		}
		if newOffset+10 > len(packet) {
			return false, 512, errors.New("truncated additional RR")
		}
		qtype := binary.BigEndian.Uint16(packet[newOffset : newOffset+2])
		rawBufSize := binary.BigEndian.Uint16(packet[newOffset+2 : newOffset+4])
		rdlen := int(binary.BigEndian.Uint16(packet[newOffset+8 : newOffset+10]))

		if newOffset+10+rdlen > len(packet) {
			return false, 512, errors.New("truncated additional RDATA")
		}

		// Check for RFC 6891 OPT RR: NAME must be root (single 0x00 byte), TYPE == 41 (OPT)
		if packet[nameOffset] == 0x00 && newOffset == nameOffset+1 && qtype == 41 {
			if rawBufSize < 512 {
				rawBufSize = 512
			}
			return true, rawBufSize, nil
		}

		offset = newOffset + 10 + rdlen
	}

	return false, 512, nil
}

// ParseEDNSBufferSize extracts the client's advertised UDP buffer size from an incoming wire DNS query,
// or returns 512 if no valid RFC 6891 OPT record is present.
func ParseEDNSBufferSize(packet []byte) uint16 {
	hasOPT, size, err := ParseEDNSOption(packet)
	if err != nil || !hasOPT {
		return 512
	}
	return size
}

// BuildDNSQueryWithEDNS constructs an RFC 1035 / RFC 6891 compliant UDP DNS Query packet.
// If ednsBufSize > 0, an RFC 6891 OPT record is appended advertising ednsBufSize.
// If ednsBufSize == 0, a standard RFC 1035 query (512-byte limit) is built.
func BuildDNSQueryWithEDNS(qname string, qtype uint16, id uint16, ednsBufSize uint16) []byte {
	var buf []byte

	// 12-byte DNS Header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // Standard query, recursion desired
	binary.BigEndian.PutUint16(header[4:6], 1)      // QDCOUNT = 1
	if ednsBufSize > 0 {
		binary.BigEndian.PutUint16(header[10:12], 1) // ARCOUNT = 1 (EDNS0 OPT RR)
	}
	buf = append(buf, header...)

	// QNAME: series of length-prefixed labels
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	for _, l := range labels {
		buf = append(buf, byte(len(l)))
		buf = append(buf, l...)
	}
	buf = append(buf, 0x00) // Root label null terminator

	// QTYPE and QCLASS
	trailer := make([]byte, 4)
	binary.BigEndian.PutUint16(trailer[0:2], qtype)
	binary.BigEndian.PutUint16(trailer[2:4], 0x0001) // Class IN
	buf = append(buf, trailer...)

	if ednsBufSize > 0 {
		optRR := []byte{
			0x00,
			0x00, 0x29, // TYPE 41 (OPT)
			byte(ednsBufSize >> 8), byte(ednsBufSize),
			0x00, 0x00, 0x00, 0x00, // TTL = 0
			0x00, 0x00, // RDLENGTH = 0
		}
		buf = append(buf, optRR...)
	}

	return buf
}

// BuildDNSQuery constructs an RFC 1035 compliant UDP DNS Query packet with default conservative EDNS0 buffer size (1232 bytes).
func BuildDNSQuery(qname string, qtype uint16, id uint16) []byte {
	return BuildDNSQueryWithEDNS(qname, qtype, id, DefaultEDNSUDPPayloadSize)
}

// ParseDNSQuery extracts QNAME, QTYPE, and transaction ID from an incoming wire DNS query.
func ParseDNSQuery(packet []byte) (id uint16, qname string, qtype uint16, err error) {
	if len(packet) < 16 {
		return 0, "", 0, ErrDNSInvalidQuery
	}

	id = binary.BigEndian.Uint16(packet[0:2])
	offset := 12

	var labels []string
	for offset < len(packet) {
		length := int(packet[offset])
		offset++
		if length == 0 {
			break // Root label
		}
		if offset+length > len(packet) {
			return 0, "", 0, ErrDNSInvalidQuery
		}
		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
	}

	if offset+4 > len(packet) {
		return 0, "", 0, ErrDNSInvalidQuery
	}
	qtype = binary.BigEndian.Uint16(packet[offset : offset+2])
	qname = strings.Join(labels, ".")

	return id, qname, qtype, nil
}

// BuildDNSTXTResponse constructs an RFC 1035 DNS response with a TXT answer record.
func BuildDNSTXTResponse(reqPacket []byte, txtPayload []byte) ([]byte, error) {
	if len(reqPacket) < 12 {
		return nil, ErrDNSInvalidQuery
	}

	id := binary.BigEndian.Uint16(reqPacket[0:2])

	// Find end of Question section
	offset := 12
	for offset < len(reqPacket) {
		length := int(reqPacket[offset])
		offset++
		if length == 0 {
			break
		}
		offset += length
	}
	offset += 4 // QTYPE + QCLASS
	if offset > len(reqPacket) {
		return nil, ErrDNSInvalidQuery
	}

	questionSec := reqPacket[12:offset]

	var resp []byte
	// Header (12 bytes)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)

	reqFlags := binary.BigEndian.Uint16(reqPacket[2:4])
	// Authoritative response flags: QR=1 (0x8000), AA=1 (0x0400), copy RD (0x0100), RA=0 (Not a recursive resolver), RCODE=0
	respFlags := uint16(0x8400) | (reqFlags & 0x0100)
	binary.BigEndian.PutUint16(hdr[2:4], respFlags)
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT = 1
	binary.BigEndian.PutUint16(hdr[6:8], 1) // ANCOUNT = 1

	hasOPT, clientBuf, _ := ParseEDNSOption(reqPacket)

	// Explicit sizing rule: effective_udp_limit = min(server_udp_cap, validated_client_advertisement)
	// - If no valid EDNS OPT record is present, use 512 bytes.
	// - For a syntactically valid advertised value from 512 bytes up to server cap, respect that value.
	// - Clamp larger advertisements to configured server cap.
	effectiveLimit := 512
	if hasOPT {
		if clientBuf > MaxSafeDNSUDPPayloadSize {
			effectiveLimit = MaxSafeDNSUDPPayloadSize
		} else if clientBuf < 512 {
			effectiveLimit = 512
		} else {
			effectiveLimit = int(clientBuf)
		}
	}

	// RDATA: One or more RFC 1035 character-strings (max 255 bytes each)
	var rdata []byte
	if len(txtPayload) == 0 {
		rdata = []byte{0x00} // empty character-string
	} else {
		for i := 0; i < len(txtPayload); i += 255 {
			end := i + 255
			if end > len(txtPayload) {
				end = len(txtPayload)
			}
			chunk := txtPayload[i:end]
			rdata = append(rdata, byte(len(chunk)))
			rdata = append(rdata, chunk...)
		}
	}

	// Exact serialized length calculation:
	// Header (12) + Question (len(questionSec)) + Answer (12 + len(rdata)) + OPT (11 if hasOPT else 0)
	expectedLen := 12 + len(questionSec) + 12 + len(rdata)
	if hasOPT {
		expectedLen += 11
	}

	if expectedLen > effectiveLimit {
		// Truncated response: TC bit set (0x0200), ANCOUNT = 0
		truncHdr := make([]byte, 12)
		binary.BigEndian.PutUint16(truncHdr[0:2], id)
		truncFlags := respFlags | 0x0200 // TC = 1
		binary.BigEndian.PutUint16(truncHdr[2:4], truncFlags)
		binary.BigEndian.PutUint16(truncHdr[4:6], 1) // QDCOUNT = 1
		binary.BigEndian.PutUint16(truncHdr[6:8], 0) // ANCOUNT = 0
		if hasOPT {
			binary.BigEndian.PutUint16(truncHdr[10:12], 1) // ARCOUNT = 1
		} else {
			binary.BigEndian.PutUint16(truncHdr[10:12], 0) // ARCOUNT = 0
		}
		var truncResp []byte
		truncResp = append(truncResp, truncHdr...)
		truncResp = append(truncResp, questionSec...)
		if hasOPT {
			optRR := []byte{
				0x00,
				0x00, 0x29,
				byte(effectiveLimit >> 8), byte(effectiveLimit),
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00,
			}
			truncResp = append(truncResp, optRR...)
		}
		return truncResp, nil
	}

	if hasOPT {
		binary.BigEndian.PutUint16(hdr[10:12], 1) // ARCOUNT = 1 (EDNS0)
	} else {
		binary.BigEndian.PutUint16(hdr[10:12], 0) // ARCOUNT = 0
	}

	resp = append(resp, hdr...)
	resp = append(resp, questionSec...)

	// Answer Section: Name pointer pointing to Question QNAME at offset 12 (0xC00C)
	ansHdr := make([]byte, 10)
	binary.BigEndian.PutUint16(ansHdr[0:2], 0xC00C) // Pointer to QNAME
	binary.BigEndian.PutUint16(ansHdr[2:4], 0x0010) // TYPE TXT
	binary.BigEndian.PutUint16(ansHdr[4:6], 0x0001) // CLASS IN
	binary.BigEndian.PutUint32(ansHdr[6:10], 0)     // TTL 0 (Do not cache)
	resp = append(resp, ansHdr...)

	rdLen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLen, uint16(len(rdata)))
	resp = append(resp, rdLen...)
	resp = append(resp, rdata...)

	if hasOPT {
		optRR := []byte{
			0x00,
			0x00, 0x29,
			byte(effectiveLimit >> 8), byte(effectiveLimit),
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
		}
		resp = append(resp, optRR...)
	}

	return resp, nil
}

// BuildDNSErrorResponse constructs an RFC 1035 error response (e.g. RCODE=5 REFUSED or RCODE=3 NXDOMAIN).
func BuildDNSErrorResponse(reqPacket []byte, rcode uint8) []byte {
	if len(reqPacket) < 12 {
		return nil
	}

	id := binary.BigEndian.Uint16(reqPacket[0:2])
	reqFlags := binary.BigEndian.Uint16(reqPacket[2:4])

	offset := 12
	for offset < len(reqPacket) {
		length := int(reqPacket[offset])
		offset++
		if length == 0 {
			break
		}
		offset += length
	}
	offset += 4
	if offset > len(reqPacket) {
		offset = len(reqPacket)
	}

	questionSec := reqPacket[12:offset]

	var resp []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	// QR=1, AA=1, copy RD, RA=0, RCODE
	respFlags := uint16(0x8400) | (reqFlags & 0x0100) | uint16(rcode&0x0F)
	binary.BigEndian.PutUint16(hdr[2:4], respFlags)
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT = 1
	binary.BigEndian.PutUint16(hdr[6:8], 0) // ANCOUNT = 0
	resp = append(resp, hdr...)
	resp = append(resp, questionSec...)

	return resp
}

// ParseDNSTXTResponse extracts and concatenates all RFC 1035 character-strings from a DNS TXT response.
func ParseDNSTXTResponse(respPacket []byte) (txtPayload []byte, err error) {
	if len(respPacket) < 12 {
		return nil, ErrDNSInvalidQuery
	}

	rcode := respPacket[3] & 0x0F
	if rcode != 0 {
		return nil, fmt.Errorf("dns response error rcode %d", rcode)
	}

	ancount := binary.BigEndian.Uint16(respPacket[6:8])
	if ancount == 0 {
		return nil, errors.New("dns response: no answer records")
	}

	// Skip Question section
	offset := 12
	for offset < len(respPacket) {
		length := int(respPacket[offset])
		offset++
		if length == 0 {
			break
		}
		offset += length
	}
	offset += 4 // Skip QTYPE + QCLASS
	if offset > len(respPacket) {
		return nil, ErrDNSInvalidQuery
	}

	// Parse Answer
	if offset+10 > len(respPacket) {
		return nil, ErrDNSInvalidQuery
	}

	// Skip Name pointer (2B), TYPE (2B), CLASS (2B), TTL (4B)
	offset += 10
	if offset+2 > len(respPacket) {
		return nil, ErrDNSInvalidQuery
	}
	rdLength := int(binary.BigEndian.Uint16(respPacket[offset : offset+2]))
	offset += 2

	if offset+rdLength > len(respPacket) {
		return nil, ErrDNSInvalidQuery
	}

	endRData := offset + rdLength
	var fullPayload []byte
	for offset < endRData {
		txtLen := int(respPacket[offset])
		offset++
		if offset+txtLen > endRData {
			return nil, ErrDNSInvalidQuery
		}
		fullPayload = append(fullPayload, respPacket[offset:offset+txtLen]...)
		offset += txtLen
	}

	return fullPayload, nil
}

// RealSocketDNSUpstreamSender transmits frames by fragmenting into DNS QNAME queries over a real UDP socket.
type RealSocketDNSUpstreamSender struct {
	conn         *net.UDPConn
	resolverAddr *net.UDPAddr
	domainSuffix string
	clientID     string
	offset       uint64
	mu           sync.Mutex
}

func NewRealSocketDNSUpstreamSender(conn *net.UDPConn, resolverAddr *net.UDPAddr, domainSuffix, clientID string) *RealSocketDNSUpstreamSender {
	return &RealSocketDNSUpstreamSender{
		conn:         conn,
		resolverAddr: resolverAddr,
		domainSuffix: domainSuffix,
		clientID:     clientID,
	}
}

func (s *RealSocketDNSUpstreamSender) SendUpstream(ctx context.Context, frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.offset++
	curOffset := s.offset

	// Split frame into labels fitting RFC 1035 length <= 63 (35 raw bytes -> 56 base32 chars)
	const chunkSize = 35
	totalParts := uint8((len(frame) + chunkSize - 1) / chunkSize)
	if totalParts == 0 {
		totalParts = 1
	}

	for i := uint8(0); i < totalParts; i++ {
		start := int(i) * chunkSize
		end := start + chunkSize
		if end > len(frame) {
			end = len(frame)
		}
		chunk := frame[start:end]

		qname := EncodeDNSQName(s.domainSuffix, s.clientID, curOffset, i, totalParts, chunk)
		queryPkt := BuildDNSQuery(qname, 0x0010 /* TXT */, uint16(curOffset+uint64(i)))

		if _, err := s.conn.WriteToUDP(queryPkt, s.resolverAddr); err != nil {
			return fmt.Errorf("dns sendto %s: %w", s.resolverAddr, err)
		}
	}

	return nil
}

func (s *RealSocketDNSUpstreamSender) Close() error {
	return s.conn.Close()
}

// RealSocketDirectUDPReceiver receives return frames directly from a real UDP socket.
type RealSocketDirectUDPReceiver struct {
	conn *net.UDPConn
}

func NewRealSocketDirectUDPReceiver(conn *net.UDPConn) *RealSocketDirectUDPReceiver {
	return &RealSocketDirectUDPReceiver{conn: conn}
}

func (r *RealSocketDirectUDPReceiver) RecvDownstream(ctx context.Context) ([]byte, error) {
	buf := make([]byte, 2048)
	n, _, err := r.conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

func (r *RealSocketDirectUDPReceiver) Close() error {
	return r.conn.Close()
}
