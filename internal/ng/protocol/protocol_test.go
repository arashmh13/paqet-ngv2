package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func TestProtocolRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		msg  Message
	}{
		{
			name: "Ping with payload",
			msg: Message{
				Cmd:     CmdPing,
				Flags:   0x00,
				Payload: []byte("heartbeat-data-123"),
			},
		},
		{
			name: "Pong empty",
			msg: Message{
				Cmd:   CmdPong,
				Flags: 0x01,
			},
		},
		{
			name: "TCP Connect",
			msg: Message{
				Cmd:   CmdTCPConnect,
				Flags: 0x00,
				Target: &TargetAddr{
					Host: "example.com",
					Port: 443,
				},
			},
		},
		{
			name: "UDP Associate",
			msg: Message{
				Cmd:   CmdUDPAssociate,
				Flags: 0x00,
				Target: &TargetAddr{
					Host: "8.8.8.8",
					Port: 53,
				},
			},
		},
		{
			name: "Terminate with error",
			msg: Message{
				Cmd:       CmdTerminate,
				ErrorCode: 504,
				Reason:    "gateway timeout",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			if err := tc.msg.Write(buf); err != nil {
				t.Fatalf("failed to write message: %v", err)
			}

			var decoded Message
			if err := decoded.Read(buf); err != nil {
				t.Fatalf("failed to read message: %v", err)
			}

			if decoded.Cmd != tc.msg.Cmd {
				t.Errorf("cmd mismatch: got 0x%02x, want 0x%02x", decoded.Cmd, tc.msg.Cmd)
			}
			if decoded.Flags != tc.msg.Flags {
				t.Errorf("flags mismatch: got 0x%02x, want 0x%02x", decoded.Flags, tc.msg.Flags)
			}

			if tc.msg.Target != nil {
				if decoded.Target == nil || decoded.Target.Host != tc.msg.Target.Host || decoded.Target.Port != tc.msg.Target.Port {
					t.Errorf("target mismatch: got %v, want %v", decoded.Target, tc.msg.Target)
				}
			}

			if len(tc.msg.Payload) > 0 {
				if !bytes.Equal(decoded.Payload, tc.msg.Payload) {
					t.Errorf("payload mismatch: got %s, want %s", string(decoded.Payload), string(tc.msg.Payload))
				}
			}

			if tc.msg.Cmd == CmdTerminate {
				if decoded.ErrorCode != tc.msg.ErrorCode || decoded.Reason != tc.msg.Reason {
					t.Errorf("terminate mismatch: code=%d reason=%s", decoded.ErrorCode, decoded.Reason)
				}
			}
		})
	}
}

func TestProtocolMalformedInput(t *testing.T) {
	// Bad magic
	badMagic := []byte{0xFF, Version, CmdPing, 0x00, 0x00, 0x00, 0x00, 0x00}
	var msg Message
	if err := msg.Read(bytes.NewReader(badMagic)); !errors.Is(err, ErrBadMagic) {
		t.Errorf("expected ErrBadMagic, got: %v", err)
	}

	// Bad version
	badVersion := []byte{Magic, 0x99, CmdPing, 0x00, 0x00, 0x00, 0x00, 0x00}
	if err := msg.Read(bytes.NewReader(badVersion)); !errors.Is(err, ErrBadVersion) {
		t.Errorf("expected ErrBadVersion, got: %v", err)
	}

	// Truncated header
	if err := msg.Read(bytes.NewReader([]byte{Magic, Version})); err == nil {
		t.Error("expected error for truncated header")
	}

	// Truncated target body
	truncatedTarget := []byte{Magic, Version, CmdTCPConnect, 0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 'a'}
	if err := msg.Read(bytes.NewReader(truncatedTarget)); err == nil {
		t.Error("expected error for truncated target body")
	}
}

func FuzzProtocolRead(f *testing.F) {
	// Seed with valid packets
	validBuf := new(bytes.Buffer)
	validMsg := Message{Cmd: CmdTCPConnect, Target: &TargetAddr{Host: "127.0.0.1", Port: 80}}
	_ = validMsg.Write(validBuf)
	f.Add(validBuf.Bytes())

	f.Add([]byte{Magic, Version, CmdPing, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var msg Message
		// Fuzzing goal: Read must never panic on arbitrary input
		_ = msg.Read(bytes.NewReader(data))
	})
}
