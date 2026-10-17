package stream

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xtaci/smux"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
	"github.com/arashmh13/paqet-ngv2/internal/ng/crypto"
	"github.com/arashmh13/paqet-ngv2/internal/ng/replay"
	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
	"github.com/arashmh13/paqet-ngv2/internal/tnet"
)

type Listener struct {
	listener net.Listener
	psk      []byte
	filter   *replay.Filter
}

func Listen(addr string, obfsCfg *conf.Obfs) (tnet.Listener, error) {
	key := []byte(obfsCfg.Key)
	if len(key) == 0 {
		return nil, fmt.Errorf("stream: encryption key is required")
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("stream: failed to listen on %s: %w", addr, err)
	}

	return &Listener{
		listener: l,
		psk:      key,
		filter:   replay.NewFilter(30 * time.Second),
	}, nil
}

func (l *Listener) Accept() (tnet.Conn, error) {
	for {
		rawConn, err := l.listener.Accept()
		if err != nil {
			return nil, err
		}

		rawConn.SetDeadline(time.Now().Add(3 * time.Second))

		var lead [3]byte
		if _, err := io.ReadFull(rawConn, lead[:]); err != nil {
			rawConn.Close()
			continue
		}

		var salt [transport.SaltSize]byte
		if lead[0] == 0x16 && lead[1] == 0x03 {
			// Decoy TLS ClientHello preamble detected: consume record
			var lenBytes [2]byte
			if _, err := io.ReadFull(rawConn, lenBytes[:]); err != nil {
				rawConn.Close()
				continue
			}
			recLen := int(binary.BigEndian.Uint16(lenBytes[:]))
			if recLen > 4096 {
				rawConn.Close()
				continue
			}
			decoyBuf := make([]byte, recLen)
			if _, err := io.ReadFull(rawConn, decoyBuf); err != nil {
				rawConn.Close()
				continue
			}
			// Read the real AEAD salt
			if _, err := io.ReadFull(rawConn, salt[:]); err != nil {
				rawConn.Close()
				continue
			}
		} else {
			// Standard AEAD stream: lead contains first 3 bytes of salt
			copy(salt[:3], lead[:])
			if _, err := io.ReadFull(rawConn, salt[3:]); err != nil {
				rawConn.Close()
				continue
			}
		}

		c2sKey, s2cKey, err := crypto.DeriveKeys(l.psk, salt[:])
		if err != nil {
			rawConn.Close()
			continue
		}

		enc, err := crypto.NewAEAD(s2cKey)
		if err != nil {
			rawConn.Close()
			continue
		}
		dec, err := crypto.NewAEAD(c2sKey)
		if err != nil {
			rawConn.Close()
			continue
		}

		secConn := &secureStreamConn{
			Conn: rawConn,
			enc:  enc,
			dec:  dec,
		}

		initFrame := make([]byte, 512)
		n, err := secConn.Read(initFrame)
		if err != nil || n < 6 {
			rawConn.Close()
			continue
		}

		packetUnix := binary.BigEndian.Uint32(initFrame[:4])
		if err := l.filter.CheckTimestamp(packetUnix, time.Now()); err != nil {
			rawConn.Close()
			continue
		}

		rawConn.SetDeadline(time.Time{})
		if tcp, ok := rawConn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}

		smuxCfg := smux.DefaultConfig()
		smuxCfg.Version = 2
		smuxCfg.MaxReceiveBuffer = 16 * 1024 * 1024
		smuxCfg.MaxStreamBuffer = 2 * 1024 * 1024
		sess, err := smux.Server(secConn, smuxCfg)
		if err != nil {
			secConn.Close()
			continue
		}

		return &Conn{
			underlying: secConn,
			session:    sess,
			rawConn:    rawConn,
		}, nil
	}
}

func (l *Listener) Close() error {
	return l.listener.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *Listener) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	// Not applicable for standard kernel TCP stream transport
}

func (l *Listener) DeleteClientTCPF(addr net.Addr) {
	// Not applicable for standard kernel TCP stream transport
}
