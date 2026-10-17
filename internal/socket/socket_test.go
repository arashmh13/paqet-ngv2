package socket

import (
	"bytes"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
)

func TestBuildAndFilterDecoyPacket(t *testing.T) {
	decoySNI := "bank.ir"
	decoyPayload := transport.BuildDecoyClientHello(decoySNI, "chrome")

	if len(decoyPayload) < 9 {
		t.Fatalf("decoyPayload too short: %d", len(decoyPayload))
	}

	// Verify that recvHandle.decode filters out packets starting with 0x16 0x03
	h := &RecvHandle{}
	d := &decoder{
		decoded: make([]gopacket.LayerType, 0, 4),
	}
	d.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&d.eth,
		&d.ip4,
		&d.ip6,
		&d.tcp,
	)
	d.parser.IgnoreUnsupported = true

	// Build a raw packet carrying the decoy payload
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    net.ParseIP("198.51.100.7").To4(),
		DstIP:    net.ParseIP("203.0.113.7").To4(),
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
		Version:  4,
		IHL:      5,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(54321),
		DstPort: layers.TCPPort(8088),
		Seq:     1000,
		Ack:     5000,
		PSH:     true,
		ACK:     true,
		Window:  65535,
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	buf := gopacket.NewSerializeBuffer()
	serOpts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, serOpts, &eth, &ip4, &tcp, gopacket.Payload(decoyPayload))
	if err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}

	rawPacketBytes := buf.Bytes()

	// Decode using recvHandle decode logic
	outBuf := make([]byte, 2048)
	h.dPool.New = func() any { return d }

	n, addr, err := h.decode(rawPacketBytes, outBuf)
	// Must return errNoPayload because it's a decoy TLS ClientHello packet
	if err != errNoPayload {
		t.Errorf("Expected errNoPayload for decoy ClientHello packet, got %v (n=%d, addr=%v)", err, n, addr)
	}

	// Now test non-decoy packet (e.g. standard Paqet datagram)
	realPayload := []byte("REAL_PAQET_OBFS_DATA_HERE")
	buf2 := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf2, serOpts, &eth, &ip4, &tcp, gopacket.Payload(realPayload))
	if err != nil {
		t.Fatalf("SerializeLayers 2 failed: %v", err)
	}

	n2, addr2, err2 := h.decode(buf2.Bytes(), outBuf)
	if err2 != nil {
		t.Fatalf("Expected non-decoy packet to be accepted, got error: %v", err2)
	}
	if n2 != len(realPayload) || !bytes.Equal(outBuf[:n2], realPayload) {
		t.Errorf("Payload mismatch: got %q, want %q", outBuf[:n2], realPayload)
	}
	if addr2.Port != 54321 {
		t.Errorf("Port mismatch: got %d, want 54321", addr2.Port)
	}
}

func TestOutOfWindowSequenceCalculation(t *testing.T) {
	decoy := transport.BuildDecoyClientHello("bank.ir", "chrome")
	decoyLen := uint32(len(decoy))

	synAckAck := uint32(100000) // This is hs.Ack (server acknowledged client ISN + 1)
	outOfWindowSeq := synAckAck - decoyLen

	// RFC 793 Window Check:
	// A segment is outside the receive window if (seq + len) <= rcv_nxt
	// Here: outOfWindowSeq + decoyLen == synAckAck (which is exactly rcv_nxt)
	// Because the segment contains 0 bytes in the forward window (all bytes are <= rcv_nxt),
	// any compliant TCP stack silently drops it without advancing rcv_nxt.
	if outOfWindowSeq+decoyLen != synAckAck {
		t.Fatalf("Sequence calculation error: %d + %d != %d", outOfWindowSeq, decoyLen, synAckAck)
	}

	if outOfWindowSeq >= synAckAck {
		t.Fatalf("Expected outOfWindowSeq (%d) < synAckAck (%d)", outOfWindowSeq, synAckAck)
	}
}
