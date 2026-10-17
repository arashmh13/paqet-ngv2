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

func Dial(addr *net.UDPAddr, cfg *conf.KCP, obfsCfg *conf.Obfs, netCfg conf.Network) (tnet.Conn, error) {
	nCfg := netCfg
	packetConn, err := socket.New(&nCfg)
	if err != nil {
		return nil, fmt.Errorf("kcp: failed to create packetconn: %w", err)
	}

	_ = packetConn.Handshake(addr)

	trConn, err := obfsCfg.Wrap(packetConn)
	if err != nil {
		packetConn.Close()
		return nil, fmt.Errorf("kcp: failed to wrap obfuscation: %w", err)
	}

	conn, err := kcp.NewConn(addr.String(), cfg.Block, cfg.Dshard, cfg.Pshard, trConn)
	if err != nil {
		trConn.Close()
		return nil, fmt.Errorf("kcp: failed to dial connection: %w", err)
	}
	aplConf(conn, cfg)

	sess, err := smux.Client(conn, smuxConf(cfg))
	if err != nil {
		conn.Close()
		trConn.Close()
		return nil, fmt.Errorf("kcp: failed to create smux session: %w", err)
	}

	return &Conn{trConn, conn, sess}, nil
}
