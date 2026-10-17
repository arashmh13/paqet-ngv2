package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
)

type decoder struct {
	parser  *gopacket.DecodingLayerParser
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	decoded []gopacket.LayerType
}

type HandshakePacket struct {
	Addr *net.UDPAddr
	SYN  bool
	ACK  bool
	Seq  uint32
	Ack  uint32
}

type RecvHandle struct {
	handle      *pcap.Handle
	dPool       sync.Pool
	mu          sync.Mutex
	onHandshake func(*HandshakePacket)
	onPeerInfo  func(ack uint32, ts uint32)
}

func NewRecvHandle(cfg *conf.Network) (*RecvHandle, error) {
	handle, err := newHandle(cfg, cfg.PCAP.Sockbuf, 65536, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction in: %v", err)
		}
	}

	filter := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	h := &RecvHandle{handle: handle}
	h.dPool.New = func() any {
		d := &decoder{decoded: make([]gopacket.LayerType, 0, 4)}
		d.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &d.eth, &d.ip4, &d.ip6, &d.tcp)
		d.parser.IgnoreUnsupported = true
		return d
	}

	return h, nil
}

func (h *RecvHandle) Read(data []byte) (int, net.Addr, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	zdata, _, err := h.handle.ZeroCopyReadPacketData()
	if err != nil {
		return 0, nil, err
	}

	return h.decode(zdata, data)
}

func (h *RecvHandle) decode(zdata, data []byte) (int, *net.UDPAddr, error) {
	d := h.dPool.Get().(*decoder)
	defer h.dPool.Put(d)

	if err := d.parser.DecodeLayers(zdata, &d.decoded); err != nil {
		return 0, nil, errNoPayload
	}

	addr := &net.UDPAddr{}
	var payload []byte
	isSYN := false
	isACK := false
	var tcpSeq, tcpAck uint32
	for _, t := range d.decoded {
		switch t {
		case layers.LayerTypeIPv4:
			addr.IP = slices.Clone(d.ip4.SrcIP)
		case layers.LayerTypeIPv6:
			addr.IP = slices.Clone(d.ip6.SrcIP)
		case layers.LayerTypeTCP:
			addr.Port = int(d.tcp.SrcPort)
			payload = d.tcp.Payload
			isSYN = d.tcp.SYN
			isACK = d.tcp.ACK
			tcpSeq = d.tcp.Seq
			tcpAck = d.tcp.Ack
			if h.onPeerInfo != nil && len(payload) > 0 {
				var peerTS uint32
				for _, opt := range d.tcp.Options {
					if opt.OptionType == layers.TCPOptionKindTimestamps && len(opt.OptionData) >= 4 {
						peerTS = binary.BigEndian.Uint32(opt.OptionData[:4])
						break
					}
				}
				h.onPeerInfo(tcpSeq+uint32(len(payload)), peerTS)
			}
		}
	}

	if h.onHandshake != nil && (isSYN || isACK) && len(payload) == 0 && addr.IP != nil {
		h.onHandshake(&HandshakePacket{
			Addr: addr,
			SYN:  isSYN,
			ACK:  isACK,
			Seq:  tcpSeq,
			Ack:  tcpAck,
		})
	}

	if addr.IP == nil || len(payload) == 0 {
		return 0, nil, errNoPayload
	}

	// Filter out decoy TLS ClientHello packets (starting with Handshake record 0x16 0x03)
	// so raw packet decoders don't treat synthetic DPI bypass frames as data.
	if len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
		return 0, nil, errNoPayload
	}

	return copy(data, payload), addr, nil
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
