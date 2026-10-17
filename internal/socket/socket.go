package socket

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/pcap"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
)

type PacketConn struct {
	cfg           *conf.Network
	sendHandle    *SendHandle
	recvHandle    *RecvHandle
	readDeadline  atomic.Value
	writeDeadline atomic.Value

	handshakeCh chan *HandshakePacket
}

func New(cfg *conf.Network) (*PacketConn, error) {
	if cfg.Port == 0 {
		cfg.Port = 32768 + rand.Intn(32768)
	}

	sendHandle, err := NewSendHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create send handle on %s: %v", cfg.Interface.Name, err)
	}

	recvHandle, err := NewRecvHandle(cfg)
	if err != nil {
		sendHandle.Close()
		return nil, fmt.Errorf("failed to create receive handle on %s: %v", cfg.Interface.Name, err)
	}

	conn := &PacketConn{
		cfg:         cfg,
		sendHandle:  sendHandle,
		recvHandle:  recvHandle,
		handshakeCh: make(chan *HandshakePacket, 16),
	}

	recvHandle.onHandshake = func(p *HandshakePacket) {
		if p.SYN && !p.ACK {
			// Server received SYN: auto reply with SYN-ACK
			serverISN := rand.Uint32()
			_ = sendHandle.WriteControl(p.Addr, conf.TCPF{SYN: true, ACK: true}, serverISN, p.Seq+1, true)
			sendHandle.curSeq.Store(serverISN + 1)
			sendHandle.peerAck.Store(p.Seq + 1)
		} else if p.SYN && p.ACK {
			// Client received SYN-ACK: notify handshake waiter
			select {
			case conn.handshakeCh <- p:
			default:
			}
		}
	}

	recvHandle.onPeerInfo = func(ack uint32, ts uint32) {
		sendHandle.SetPeerInfo(ack, ts)
	}

	return conn, nil
}

func (c *PacketConn) Handshake(dst *net.UDPAddr) error {
	clientISN := rand.Uint32()
	done := make(chan struct{})
	defer close(done)

	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-done:
				return
			default:
				_, _, _ = c.recvHandle.Read(buf)
			}
		}
	}()

	for attempt := 0; attempt < 3; attempt++ {
		if err := c.sendHandle.WriteControl(dst, conf.TCPF{SYN: true}, clientISN, 0, true); err != nil {
			return err
		}
		select {
		case hs := <-c.handshakeCh:
			if hs.Addr.IP.Equal(dst.IP) && hs.Addr.Port == dst.Port {
				_ = c.sendHandle.WriteControl(dst, conf.TCPF{ACK: true}, hs.Ack, hs.Seq+1, false)
				c.sendHandle.curSeq.Store(hs.Ack)
				c.sendHandle.peerAck.Store(hs.Seq + 1)

				// If SNI decoy injection is enabled, emit out-of-window raw TCP packet (wrong_seq)
				// As established in reference projects (patterniha/SNI-Spoofing, aleskxyz),
				// out-of-window sequence number (seq = hs.Ack - len(payload)) tricks DPI into
				// whitelisting the flow while destination OS kernel silently discards the segment.
				if c.cfg.SNI != nil && c.cfg.SNI.Decoy != "" {
					decoy := transport.BuildDecoyClientHello(c.cfg.SNI.Decoy, c.cfg.SNI.Preset)
					outOfWindowSeq := hs.Ack - uint32(len(decoy))
					_ = c.sendHandle.WriteRawDecoy(dst, decoy, outOfWindowSeq, hs.Seq+1)
				}
				return nil
			}
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil
}

func (c *PacketConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	for {
		if d, ok := c.readDeadline.Load().(time.Time); ok && !d.IsZero() && !time.Now().Before(d) {
			return 0, nil, os.ErrDeadlineExceeded
		}

		n, addr, err := c.recvHandle.Read(data)
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) || errors.Is(err, errNoPayload) {
				continue
			}
			return 0, nil, err
		}

		return n, addr, nil
	}
}

func (c *PacketConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	if d, ok := c.writeDeadline.Load().(time.Time); ok && !d.IsZero() && !time.Now().Before(d) {
		return 0, os.ErrDeadlineExceeded
	}

	daddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, net.InvalidAddrError("invalid address")
	}

	err = c.sendHandle.Write(data, daddr)
	if err != nil {
		return 0, err
	}

	return len(data), nil
}

func (c *PacketConn) Close() error {
	if c.sendHandle != nil {
		c.sendHandle.Close()
	}
	if c.recvHandle != nil {
		c.recvHandle.Close()
	}
	return nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	return nil
	// return &net.UDPAddr{
	// 	IP:   append([]byte(nil), c.cfg.PrimaryAddr().IP...),
	// 	Port: c.cfg.PrimaryAddr().Port,
	// 	Zone: c.cfg.PrimaryAddr().Zone,
	// }
}

func (c *PacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetDSCP(dscp int) error {
	return nil
}

func (c *PacketConn) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	c.sendHandle.setClientTCPF(addr, f)
}

func (c *PacketConn) DeleteClientTCPF(addr net.Addr) {
	c.sendHandle.deleteClientTCPF(addr)
}
