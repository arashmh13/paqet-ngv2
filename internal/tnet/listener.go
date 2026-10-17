package tnet

import (
	"net"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
)

type Listener interface {
	Accept() (Conn, error)
	Close() error
	Addr() net.Addr
	SetClientTCPF(addr net.Addr, f []conf.TCPF)
	DeleteClientTCPF(addr net.Addr)
}
