package client

import (
	"context"
	"sync"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
	"github.com/arashmh13/paqet-ngv2/internal/flog"
	"github.com/arashmh13/paqet-ngv2/internal/ng/transport"
	"github.com/arashmh13/paqet-ngv2/internal/pkg/iterator"
)

type Client struct {
	cfg            *conf.Conf
	iter           *iterator.Iterator[*timedConn]
	udpPool        *udpPool
	recoveryEngine *transport.RecoveryStateMachine
	mu             sync.Mutex
}

func New(cfg *conf.Conf) (*Client, error) {
	c := &Client{
		cfg:     cfg,
		iter:    &iterator.Iterator[*timedConn]{},
		udpPool: newUDPPool(),
	}
	return c, nil
}

// SetRecoveryEngine attaches an integrated recovery state machine to the client and its connections.
func (c *Client) SetRecoveryEngine(re *transport.RecoveryStateMachine) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recoveryEngine = re
	if c.iter != nil {
		for _, tc := range c.iter.Items {
			tc.recoveryEngine = re
		}
	}
}

// RecoveryEngine returns the attached recovery state machine.
func (c *Client) RecoveryEngine() *transport.RecoveryStateMachine {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recoveryEngine
}

func (c *Client) Start(ctx context.Context) error {
	for i := range c.cfg.Transport.Conn {
		tc, err := newTimedConn(c.cfg, i, c.recoveryEngine)
		if err != nil {
			flog.Errorf("failed to create connection %d: %v", i+1, err)
			return err
		}
		c.iter.Items = append(c.iter.Items, tc)
	}
	context.AfterFunc(ctx, func() {
		for _, tc := range c.iter.Items {
			tc.close()
		}
	})

	go c.ticker(ctx)
	go c.udpPool.ticker(ctx)

	ipv4Addr := "<nil>"
	ipv6Addr := "<nil>"
	if c.cfg.Network.IPv4.Addr != nil {
		ipv4Addr = c.cfg.Network.IPv4.Addr.IP.String()
	}
	if c.cfg.Network.IPv6.Addr != nil {
		ipv6Addr = c.cfg.Network.IPv6.Addr.IP.String()
	}
	flog.Infof("client IPv4:%s IPv6:%s -> %s (%d connections)", ipv4Addr, ipv6Addr, c.cfg.Server.Addr, len(c.iter.Items))
	return nil
}
