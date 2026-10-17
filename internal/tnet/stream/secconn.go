package stream

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/arashmh13/paqet-ngv2/internal/ng/crypto"
	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
)

type secureStreamConn struct {
	net.Conn
	enc      cipher.AEAD
	dec      cipher.AEAD
	encNonce uint64
	decNonce uint64
	readBuf  []byte
	writeMu  sync.Mutex
	readMu   sync.Mutex
}

func (s *secureStreamConn) makeNonce(counter uint64) [crypto.NonceSize]byte {
	var n [crypto.NonceSize]byte
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func (s *secureStreamConn) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	totalSent := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > transport.MaxChunkSize {
			chunkSize = transport.MaxChunkSize
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]

		nonce := s.makeNonce(s.encNonce)
		s.encNonce++

		frame := make([]byte, transport.ChunkHeaderLen, transport.ChunkHeaderLen+chunkSize+crypto.TagSize)
		ciphertext := s.enc.Seal(frame, nonce[:], chunk, nil)
		frameLen := uint16(len(ciphertext) - transport.ChunkHeaderLen)
		binary.BigEndian.PutUint16(ciphertext[:transport.ChunkHeaderLen], frameLen)

		if _, err := s.Conn.Write(ciphertext); err != nil {
			return totalSent, err
		}
		totalSent += chunkSize
	}
	return totalSent, nil
}

func (s *secureStreamConn) Read(b []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	if len(s.readBuf) > 0 {
		n := copy(b, s.readBuf)
		s.readBuf = s.readBuf[n:]
		return n, nil
	}

	var hdr [transport.ChunkHeaderLen]byte
	if _, err := io.ReadFull(s.Conn, hdr[:]); err != nil {
		return 0, err
	}

	frameLen := int(binary.BigEndian.Uint16(hdr[:]))
	if frameLen > transport.MaxChunkSize+crypto.TagSize+512 {
		return 0, errors.New("stream: chunk exceeds max frame length")
	}

	ciphertext := make([]byte, frameLen)
	if _, err := io.ReadFull(s.Conn, ciphertext); err != nil {
		return 0, err
	}

	nonce := s.makeNonce(s.decNonce)
	s.decNonce++

	plaintext, err := s.dec.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("stream: %w", crypto.ErrDecrypt)
	}

	n := copy(b, plaintext)
	if n < len(plaintext) {
		s.readBuf = append(s.readBuf[:0], plaintext[n:]...)
	}
	return n, nil
}
