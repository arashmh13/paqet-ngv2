package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Magic   byte = 0x50 // 'P'
	Version byte = 0x02 // Paqet-NG Version 2

	HeaderLen = 8 // Magic(1) + Version(1) + Cmd(1) + Flags(1) + BodyLen(4)

	MaxBodyLen = 65536
	MaxHostLen = 253
)

type Cmd = byte

const (
	CmdPing         Cmd = 0x01
	CmdPong         Cmd = 0x02
	CmdTCPConnect   Cmd = 0x03
	CmdUDPAssociate Cmd = 0x04
	CmdTerminate    Cmd = 0x05
)

var (
	ErrBadMagic   = errors.New("protocol: invalid magic byte")
	ErrBadVersion = errors.New("protocol: unsupported protocol version")
	ErrBodyTooBig = errors.New("protocol: body exceeds maximum allowed length")
	ErrTruncated  = errors.New("protocol: truncated message")
)

type TargetAddr struct {
	Host string
	Port uint16
}

func (a *TargetAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s:%d", a.Host, a.Port)
}

// Message represents a Paqet-NG logical frame.
type Message struct {
	Cmd       Cmd
	Flags     byte
	Target    *TargetAddr
	Payload   []byte
	ErrorCode uint16
	Reason    string
}

// Write serializes the message to an io.Writer.
func (m *Message) Write(w io.Writer) error {
	var body []byte

	switch m.Cmd {
	case CmdPing, CmdPong:
		body = m.Payload

	case CmdTCPConnect, CmdUDPAssociate:
		if m.Target == nil {
			return errors.New("protocol: target address is required")
		}
		hostBytes := []byte(m.Target.Host)
		if len(hostBytes) > MaxHostLen {
			return fmt.Errorf("protocol: host length %d exceeds max %d", len(hostBytes), MaxHostLen)
		}
		body = make([]byte, 1+len(hostBytes)+2)
		body[0] = byte(len(hostBytes))
		copy(body[1:1+len(hostBytes)], hostBytes)
		binary.BigEndian.PutUint16(body[1+len(hostBytes):], m.Target.Port)

	case CmdTerminate:
		reasonBytes := []byte(m.Reason)
		body = make([]byte, 2+len(reasonBytes))
		binary.BigEndian.PutUint16(body[:2], m.ErrorCode)
		copy(body[2:], reasonBytes)

	default:
		return fmt.Errorf("protocol: unknown command 0x%02x", m.Cmd)
	}

	if len(body) > MaxBodyLen {
		return ErrBodyTooBig
	}

	hdr := make([]byte, HeaderLen)
	hdr[0] = Magic
	hdr[1] = Version
	hdr[2] = m.Cmd
	hdr[3] = m.Flags
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(body)))

	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

// Read deserializes a message from an io.Reader.
func (m *Message) Read(r io.Reader) error {
	hdr := make([]byte, HeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return err
	}

	if hdr[0] != Magic {
		return fmt.Errorf("%w: got 0x%02x, want 0x%02x", ErrBadMagic, hdr[0], Magic)
	}
	if hdr[1] != Version {
		return fmt.Errorf("%w: got 0x%02x, want 0x%02x", ErrBadVersion, hdr[1], Version)
	}

	m.Cmd = hdr[2]
	m.Flags = hdr[3]
	bodyLen := binary.BigEndian.Uint32(hdr[4:])

	if bodyLen > MaxBodyLen {
		return ErrBodyTooBig
	}

	var body []byte
	if bodyLen > 0 {
		body = make([]byte, bodyLen)
		if _, err := io.ReadFull(r, body); err != nil {
			return err
		}
	}

	switch m.Cmd {
	case CmdPing, CmdPong:
		m.Payload = body

	case CmdTCPConnect, CmdUDPAssociate:
		if len(body) < 3 {
			return ErrTruncated
		}
		hostLen := int(body[0])
		if hostLen > MaxHostLen || 1+hostLen+2 != len(body) {
			return errors.New("protocol: malformed target address body")
		}
		host := string(body[1 : 1+hostLen])
		port := binary.BigEndian.Uint16(body[1+hostLen:])
		m.Target = &TargetAddr{Host: host, Port: port}

	case CmdTerminate:
		if len(body) < 2 {
			return ErrTruncated
		}
		m.ErrorCode = binary.BigEndian.Uint16(body[:2])
		m.Reason = string(body[2:])

	default:
		return fmt.Errorf("protocol: unknown command 0x%02x", m.Cmd)
	}

	return nil
}
