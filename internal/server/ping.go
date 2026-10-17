package server

import (
	"github.com/arashmh13/paqet-ngv2/internal/flog"
	"github.com/arashmh13/paqet-ngv2/internal/protocol"
	"github.com/arashmh13/paqet-ngv2/internal/tnet"
)

func (s *Server) handlePing(strm tnet.Strm) {
	p := protocol.Proto{Type: protocol.PPONG}
	if err := p.Write(strm); err != nil {
		flog.Errorf("failed to send pong on stream %d: %v", strm.SID(), err)
	}
}
