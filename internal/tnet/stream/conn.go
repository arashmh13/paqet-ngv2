package stream

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xtaci/smux"

	"github.com/arashmh13/paqet-ngv2/internal/protocol"
	"github.com/arashmh13/paqet-ngv2/internal/tnet"
)

type Conn struct {
	underlying io.Closer
	session    *smux.Session
	rawConn    net.Conn
}

func (c *Conn) OpenStrm() (tnet.Strm, error) {
	strm, err := c.session.OpenStream()
	if err != nil {
		return nil, err
	}
	return &Strm{strm}, nil
}

func (c *Conn) AcceptStrm() (tnet.Strm, error) {
	strm, err := c.session.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &Strm{strm}, nil
}

func (c *Conn) Ping(wait bool) error {
	strm, err := c.session.OpenStream()
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}
	defer strm.Close()

	if wait {
		p := protocol.Proto{Type: protocol.PPING}
		if err := p.Write(strm); err != nil {
			return fmt.Errorf("strm ping write failed: %w", err)
		}
		if err := p.Read(strm); err != nil {
			return fmt.Errorf("strm ping read failed: %w", err)
		}
		if p.Type != protocol.PPONG {
			return fmt.Errorf("strm pong failed: unexpected type %d", p.Type)
		}
	}
	return nil
}

func (c *Conn) Close() error {
	var err1, err2 error
	if c.session != nil {
		err1 = c.session.Close()
	}
	if c.underlying != nil {
		err2 = c.underlying.Close()
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *Conn) LocalAddr() net.Addr {
	if c.rawConn != nil {
		return c.rawConn.LocalAddr()
	}
	return c.session.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	if c.rawConn != nil {
		return c.rawConn.RemoteAddr()
	}
	return c.session.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	if c.rawConn != nil {
		return c.rawConn.SetDeadline(t)
	}
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.rawConn != nil {
		return c.rawConn.SetReadDeadline(t)
	}
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.rawConn != nil {
		return c.rawConn.SetWriteDeadline(t)
	}
	return nil
}
