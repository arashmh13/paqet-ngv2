package kcp

import (
	"fmt"
	"net"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
	"github.com/arashmh13/paqet-ngv2/internal/socket"
	"github.com/arashmh13/paqet-ngv2/internal/tnet"
)

type Listener struct {
	rawConn    *socket.PacketConn
	packetConn net.PacketConn
	cfg        *conf.KCP
	listener   *kcp.Listener
}

func Listen(cfg *conf.KCP, obfsCfg *conf.Obfs, netCfg conf.Network) (tnet.Listener, error) {
	nCfg := netCfg
	packetConn, err := socket.New(&nCfg)
	if err != nil {
		return nil, fmt.Errorf("kcp: failed to create packetconn: %w", err)
	}

	trConn, err := obfsCfg.Wrap(packetConn)
	if err != nil {
		packetConn.Close()
		return nil, fmt.Errorf("kcp: failed to wrap obfuscation: %w", err)
	}

	l, err := kcp.ServeConn(cfg.Block, cfg.Dshard, cfg.Pshard, trConn)
	if err != nil {
		trConn.Close()
		return nil, fmt.Errorf("kcp: failed to serve connection: %w", err)
	}

	return &Listener{rawConn: packetConn, packetConn: trConn, cfg: cfg, listener: l}, nil
}

func (l *Listener) Accept() (tnet.Conn, error) {
	conn, err := l.listener.AcceptKCP()
	if err != nil {
		return nil, fmt.Errorf("kcp: failed to accept connection: %w", err)
	}
	aplConf(conn, l.cfg)
	sess, err := smux.Server(conn, smuxConf(l.cfg))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("kcp: failed to create smux session: %w", err)
	}
	return &Conn{nil, conn, sess}, nil
}

func (l *Listener) Close() error {
	var err error
	if l.listener != nil {
		if e := l.listener.Close(); e != nil {
			err = e
		}
	}
	if l.packetConn != nil {
		if e := l.packetConn.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *Listener) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	l.rawConn.SetClientTCPF(addr, f)
}

func (l *Listener) DeleteClientTCPF(addr net.Addr) {
	l.rawConn.DeleteClientTCPF(addr)
}
