package client

import (
	"context"
	"fmt"
	"time"

	"github.com/arashmh13/paqet-ngv2/internal/flog"
	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
	"github.com/arashmh13/paqet-ngv2/internal/tnet"
)

func (c *Client) newConn() (tnet.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	autoExpire := 300
	tc := c.iter.Next()

	tc.mu.Lock()
	defer tc.mu.Unlock()

	desired := tc.desiredIdentity()
	needsRecreate := false

	if tc.conn == nil {
		needsRecreate = true
	} else if !tc.currentIdentity.Matches(desired) {
		flog.Infof("[CONNECTION-SWITCH] Connection identity mismatch (current: %s %s gen=%d recov=%v, desired: %s %s gen=%d recov=%v), recreating...",
			tc.currentIdentity.RemoteAddr, tc.currentIdentity.TransportMode, tc.currentIdentity.Generation, tc.currentIdentity.IsRecovery,
			desired.RemoteAddr, desired.TransportMode, desired.Generation, desired.IsRecovery)
		needsRecreate = true
	} else {
		// Connection matches desired identity; test if alive
		if err := tc.conn.Ping(false); err != nil {
			needsRecreate = true
		}
	}

	if needsRecreate {
		if tc.conn != nil {
			_ = tc.conn.Close()
			tc.conn = nil
		}
		conn, id, err := tc.createConn()
		if err != nil {
			if c.recoveryEngine != nil && !desired.IsRecovery && c.recoveryEngine.CurrentState() != transport.StateRecoveryReady {
				c.recoveryEngine.ReportPrimaryFailure(err)
				_, _ = c.recoveryEngine.Step(context.Background())
			}
			return nil, err
		}

		// Double-check: verify desired identity did not change while createConn was dialed
		currentDesired := tc.desiredIdentity()
		if !id.Matches(currentDesired) {
			_ = conn.Close()
			return nil, fmt.Errorf("connection identity superseded by state transition during dial")
		}

		tc.conn = conn
		tc.currentIdentity = id
		tc.expire = time.Now().Add(time.Duration(autoExpire) * time.Second)

		// Send TCPF only if primary
		if !id.IsRecovery {
			go tc.sendTCPF(tc.conn)
		}
	} else {
		if !tc.currentIdentity.IsRecovery {
			go tc.sendTCPF(tc.conn)
		}
	}
	return tc.conn, nil
}

func (c *Client) newStrm(ctx context.Context) (tnet.Strm, error) {
	maxRetries := 5
	backoff := 25 * time.Millisecond
	for attempt := 0; attempt < maxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := c.newConn()
		if err != nil {
			flog.Debugf("failed to open conn (attempt %d/%d), retrying: %v", attempt+1, maxRetries, err)
			select {
			case <-time.After(backoff):
				backoff *= 2
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		strm, err := conn.OpenStrm()
		if err != nil {
			flog.Debugf("failed to open stream (attempt %d/%d), retrying: %v", attempt+1, maxRetries, err)
			select {
			case <-time.After(backoff):
				backoff *= 2
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return strm, nil
	}
	return nil, fmt.Errorf("exceeded max connection retries (%d)", maxRetries)
}
