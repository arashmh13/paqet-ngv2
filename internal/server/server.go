package server

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
	"github.com/arashmh13/paqet-ngv2/internal/flog"
	"github.com/arashmh13/paqet-ngv2/internal/tnet"
	"github.com/arashmh13/paqet-ngv2/internal/tnet/kcp"
	"github.com/arashmh13/paqet-ngv2/internal/tnet/stream"
)

type Server struct {
	cfg       *conf.Conf
	listeners []tnet.Listener
	conns     []tnet.Conn
	mu        sync.Mutex
}

func New(cfg *conf.Conf) (*Server, error) {
	s := &Server{cfg: cfg}
	return s, nil
}

func (s *Server) Start(ctx context.Context) error {
	endpoints := s.cfg.Listen.Endpoints
	if len(endpoints) == 0 && s.cfg.Listen.Addr != nil {
		endpoints = []*net.UDPAddr{s.cfg.Listen.Addr}
	}

	for _, ep := range endpoints {
		var listener tnet.Listener
		var err error

		switch s.cfg.Transport.Protocol {
		case "tls", "tls-stream":
			listener, err = stream.ListenTLS(ep.String(), s.cfg.Transport.Obfs, s.cfg.Transport.TLS)
			if err != nil {
				return fmt.Errorf("could not start TLS listener on %s: %w", ep.String(), err)
			}
			flog.Infof("server listening for TLS stream connections on %s", ep.String())
		case "stream", "aead-stream", "sni-assisted", "auto":
			listener, err = stream.Listen(ep.String(), s.cfg.Transport.Obfs)
			if err != nil {
				return fmt.Errorf("could not start stream listener on %s: %w", ep.String(), err)
			}
			flog.Infof("server listening for stream connections on %s", ep.String())
		default:
			listener, err = kcp.Listen(s.cfg.Transport.KCP, s.cfg.Transport.Obfs, s.cfg.Network)
			if err != nil {
				return fmt.Errorf("could not start KCP listener on :%d: %w", ep.Port, err)
			}
			flog.Infof("server listening for packets on :%d", ep.Port)
		}

		s.listeners = append(s.listeners, listener)
		go s.listen(ctx, listener)
	}

	context.AfterFunc(ctx, func() {
		for _, l := range s.listeners {
			_ = l.Close()
		}
		s.mu.Lock()
		for _, c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
	})

	return nil
}

func (s *Server) listen(ctx context.Context, listener tnet.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		flog.Infof("accepted new connection from %s (local: %s)", conn.RemoteAddr(), conn.LocalAddr())

		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.mu.Unlock()

		go func() {
			defer conn.Close()
			defer listener.DeleteClientTCPF(conn.RemoteAddr())
			s.handleConn(ctx, conn)
		}()
	}
}
