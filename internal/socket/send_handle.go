package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
	"github.com/arashmh13/paqet-ngv2/internal/pkg/hash"
	"github.com/arashmh13/paqet-ngv2/internal/pkg/iterator"
)

type tcpF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
	mu         sync.RWMutex
}

type encoder struct {
	eth layers.Ethernet
	ip4 layers.IPv4
	ip6 layers.IPv6
	tcp layers.TCP

	opts [5]layers.TCPOption
	ts   [8]byte
	mss  [2]byte
	ws   [1]byte

	buf gopacket.SerializeBuffer
}

type SendHandle struct {
	handle      *pcap.Handle
	writeMu     sync.Mutex
	srcIPv4     net.IP
	srcIPv4RHWA net.HardwareAddr
	srcIPv6     net.IP
	srcIPv6RHWA net.HardwareAddr
	srcPort     uint16
	time        uint32
	tsCounter   atomic.Uint32
	curSeq      atomic.Uint32
	peerAck     atomic.Uint32
	peerTS      atomic.Uint32
	tcpF        tcpF
	ePool       sync.Pool
}

func NewSendHandle(cfg *conf.Network) (*SendHandle, error) {
	handle, err := newHandle(cfg, 256*1024, 128, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionOut); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction out: %v", err)
		}
	}

	if err := handle.SetBPFFilter("less 0"); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	sh := &SendHandle{
		handle:  handle,
		srcPort: uint16(cfg.Port),
		tcpF:    tcpF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		time:    uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		ePool: sync.Pool{
			New: func() any {
				return &encoder{
					eth: layers.Ethernet{SrcMAC: cfg.Interface.HardwareAddr},
					mss: [2]byte{0x05, 0xb4},
					ws:  [1]byte{8},
					buf: gopacket.NewSerializeBuffer(),
				}
			},
		},
	}
	if cfg.IPv4.Addr != nil {
		sh.srcIPv4 = cfg.IPv4.Addr.IP
		sh.srcIPv4RHWA = cfg.IPv4.Router
	}
	if cfg.IPv6.Addr != nil {
		sh.srcIPv6 = cfg.IPv6.Addr.IP
		sh.srcIPv6RHWA = cfg.IPv6.Router
	}
	sh.curSeq.Store(sh.time)
	return sh, nil
}

func (h *SendHandle) SetPeerInfo(ack uint32, ts uint32) {
	if ack > 0 {
		h.peerAck.Store(ack)
	}
	if ts > 0 {
		h.peerTS.Store(ts)
	}
}

func (h *SendHandle) buildIPv4Header(e *encoder, dstIP net.IP) {
	e.ip4 = layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      0,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    h.srcIPv4,
		DstIP:    dstIP,
	}
}

func (h *SendHandle) buildIPv6Header(e *encoder, dstIP net.IP) {
	e.ip6 = layers.IPv6{
		Version:      6,
		TrafficClass: 0,
		HopLimit:     64,
		NextHeader:   layers.IPProtocolTCP,
		SrcIP:        h.srcIPv6,
		DstIP:        dstIP,
	}
}

func (h *SendHandle) buildTCPHeader(e *encoder, dstPort uint16, f conf.TCPF, payloadLen int) {
	e.tcp = layers.TCP{
		SrcPort: layers.TCPPort(h.srcPort),
		DstPort: layers.TCPPort(dstPort),
		FIN:     f.FIN, SYN: f.SYN, RST: f.RST, PSH: f.PSH, ACK: f.ACK, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS,
		Window: 65535,
	}

	counter := h.tsCounter.Add(1)
	tsVal := h.time + (counter >> 3)
	opts := e.opts[:0]
	if f.SYN {
		binary.BigEndian.PutUint32(e.ts[0:4], tsVal)
		binary.BigEndian.PutUint32(e.ts[4:8], 0)
		opts = append(opts,
			layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: e.mss[:]},
			layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: e.ts[:]},
			layers.TCPOption{OptionType: layers.TCPOptionKindNop},
			layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: e.ws[:]},
		)
		e.tcp.Seq = 1 + (counter & 0x7)
		e.tcp.Ack = 0
		if f.ACK {
			e.tcp.Ack = e.tcp.Seq + 1
		}
	} else {
		peerTS := h.peerTS.Load()
		tsEcr := peerTS
		if tsEcr == 0 {
			tsEcr = tsVal - 50
		}
		binary.BigEndian.PutUint32(e.ts[0:4], tsVal)
		binary.BigEndian.PutUint32(e.ts[4:8], tsEcr)
		opts = append(opts,
			layers.TCPOption{OptionType: layers.TCPOptionKindNop},
			layers.TCPOption{OptionType: layers.TCPOptionKindNop},
			layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: e.ts[:]},
		)

		pLen := uint32(payloadLen)
		if pLen == 0 {
			pLen = 1
		}
		seq := h.curSeq.Add(pLen) - pLen
		e.tcp.Seq = seq

		peerAck := h.peerAck.Load()
		if peerAck > 0 {
			e.tcp.Ack = peerAck
		} else {
			e.tcp.Ack = seq + 1400
		}
	}
	e.tcp.Options = opts
}

func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr) error {
	e := h.ePool.Get().(*encoder)
	defer func() {
		e.buf.Clear()
		h.ePool.Put(e)
	}()

	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	h.buildTCPHeader(e, dstPort, h.getClientTCPF(dstIP, dstPort), len(payload))

	var ipLayer gopacket.SerializableLayer
	if dstIP.To4() != nil {
		h.buildIPv4Header(e, dstIP)
		ipLayer = &e.ip4
		e.tcp.SetNetworkLayerForChecksum(&e.ip4)
		e.eth.DstMAC = h.srcIPv4RHWA
		e.eth.EthernetType = layers.EthernetTypeIPv4
	} else {
		h.buildIPv6Header(e, dstIP)
		ipLayer = &e.ip6
		e.tcp.SetNetworkLayerForChecksum(&e.ip6)
		e.eth.DstMAC = h.srcIPv6RHWA
		e.eth.EthernetType = layers.EthernetTypeIPv6
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(e.buf, opts, &e.eth, ipLayer, &e.tcp, gopacket.Payload(payload)); err != nil {
		return err
	}

	// pcap_sendpacket is not guaranteed thread-safe.
	h.writeMu.Lock()
	err := h.handle.WritePacketData(e.buf.Bytes())
	h.writeMu.Unlock()
	return err
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	h.tcpF.mu.RLock()
	defer h.tcpF.mu.RUnlock()
	if ff := h.tcpF.clientTCPF[hash.IPAddr(dstIP, dstPort)]; ff != nil {
		return ff.Next()
	}
	return h.tcpF.tcpF.Next()
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
	a, ok := addr.(*net.UDPAddr)
	if !ok {
		return
	}
	h.tcpF.mu.Lock()
	h.tcpF.clientTCPF[hash.IPAddr(a.IP, uint16(a.Port))] = &iterator.Iterator[conf.TCPF]{Items: f}
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) deleteClientTCPF(addr net.Addr) {
	a, ok := addr.(*net.UDPAddr)
	if !ok {
		return
	}
	h.tcpF.mu.Lock()
	delete(h.tcpF.clientTCPF, hash.IPAddr(a.IP, uint16(a.Port)))
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) WriteControl(addr *net.UDPAddr, f conf.TCPF, seq, ack uint32, synOpts bool) error {
	e := h.ePool.Get().(*encoder)
	defer func() {
		e.buf.Clear()
		h.ePool.Put(e)
	}()

	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	e.tcp = layers.TCP{
		SrcPort: layers.TCPPort(h.srcPort),
		DstPort: layers.TCPPort(dstPort),
		FIN:     f.FIN, SYN: f.SYN, RST: f.RST, PSH: f.PSH, ACK: f.ACK, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS,
		Window: 65535,
		Seq:    seq,
		Ack:    ack,
	}

	counter := h.tsCounter.Add(1)
	tsVal := h.time + (counter >> 3)
	opts := e.opts[:0]
	if synOpts {
		binary.BigEndian.PutUint32(e.ts[0:4], tsVal)
		binary.BigEndian.PutUint32(e.ts[4:8], 0)
		opts = append(opts,
			layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: e.mss[:]},
			layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: e.ts[:]},
			layers.TCPOption{OptionType: layers.TCPOptionKindNop},
			layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: e.ws[:]},
		)
	} else {
		tsEcr := tsVal - 50
		binary.BigEndian.PutUint32(e.ts[0:4], tsVal)
		binary.BigEndian.PutUint32(e.ts[4:8], tsEcr)
		opts = append(opts,
			layers.TCPOption{OptionType: layers.TCPOptionKindNop},
			layers.TCPOption{OptionType: layers.TCPOptionKindNop},
			layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: e.ts[:]},
		)
	}
	e.tcp.Options = opts

	var ipLayer gopacket.SerializableLayer
	if dstIP.To4() != nil {
		h.buildIPv4Header(e, dstIP)
		ipLayer = &e.ip4
		e.tcp.SetNetworkLayerForChecksum(&e.ip4)
		e.eth.DstMAC = h.srcIPv4RHWA
		e.eth.EthernetType = layers.EthernetTypeIPv4
	} else {
		h.buildIPv6Header(e, dstIP)
		ipLayer = &e.ip6
		e.tcp.SetNetworkLayerForChecksum(&e.ip6)
		e.eth.DstMAC = h.srcIPv6RHWA
		e.eth.EthernetType = layers.EthernetTypeIPv6
	}

	serOpts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(e.buf, serOpts, &e.eth, ipLayer, &e.tcp); err != nil {
		return err
	}

	h.writeMu.Lock()
	err := h.handle.WritePacketData(e.buf.Bytes())
	h.writeMu.Unlock()
	return err
}

func (h *SendHandle) WriteRawDecoy(addr *net.UDPAddr, payload []byte, seq, ack uint32) error {
	e := h.ePool.Get().(*encoder)
	defer func() {
		e.buf.Clear()
		h.ePool.Put(e)
	}()

	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	e.tcp = layers.TCP{
		SrcPort: layers.TCPPort(h.srcPort),
		DstPort: layers.TCPPort(dstPort),
		PSH:     true,
		ACK:     true,
		Window:  65535,
		Seq:     seq,
		Ack:     ack,
	}

	counter := h.tsCounter.Add(1)
	tsVal := h.time + (counter >> 3)
	peerTS := h.peerTS.Load()
	tsEcr := peerTS
	if tsEcr == 0 {
		tsEcr = tsVal - 50
	}
	binary.BigEndian.PutUint32(e.ts[0:4], tsVal)
	binary.BigEndian.PutUint32(e.ts[4:8], tsEcr)
	opts := e.opts[:0]
	opts = append(opts,
		layers.TCPOption{OptionType: layers.TCPOptionKindNop},
		layers.TCPOption{OptionType: layers.TCPOptionKindNop},
		layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: e.ts[:]},
	)
	e.tcp.Options = opts

	var ipLayer gopacket.SerializableLayer
	if dstIP.To4() != nil {
		h.buildIPv4Header(e, dstIP)
		ipLayer = &e.ip4
		e.tcp.SetNetworkLayerForChecksum(&e.ip4)
		e.eth.DstMAC = h.srcIPv4RHWA
		e.eth.EthernetType = layers.EthernetTypeIPv4
	} else {
		h.buildIPv6Header(e, dstIP)
		ipLayer = &e.ip6
		e.tcp.SetNetworkLayerForChecksum(&e.ip6)
		e.eth.DstMAC = h.srcIPv6RHWA
		e.eth.EthernetType = layers.EthernetTypeIPv6
	}

	serOpts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(e.buf, serOpts, &e.eth, ipLayer, &e.tcp, gopacket.Payload(payload)); err != nil {
		return err
	}

	h.writeMu.Lock()
	err := h.handle.WritePacketData(e.buf.Bytes())
	h.writeMu.Unlock()
	return err
}

func (h *SendHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
