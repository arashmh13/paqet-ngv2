package conf

import (
	"fmt"
	"net"
)

type Server struct {
	Addr_     string         `yaml:"addr"`
	Addrs     []string       `yaml:"addrs"`
	Addr      *net.UDPAddr   `yaml:"-"`
	Endpoints []*net.UDPAddr `yaml:"-"`
}

func (s *Server) setDefaults() {}
func (s *Server) validate() []error {
	var errors []error

	if len(s.Addrs) > 0 {
		for i, aStr := range s.Addrs {
			addr, err := validateAddr(aStr, true)
			if err != nil {
				errors = append(errors, fmt.Errorf("addrs[%d] %v", i, err))
			} else {
				s.Endpoints = append(s.Endpoints, addr)
			}
		}
		if len(s.Endpoints) > 0 {
			s.Addr = s.Endpoints[0]
			s.Addr_ = s.Addrs[0]
		}
	} else if s.Addr_ != "" {
		addr, err := validateAddr(s.Addr_, true)
		if err != nil {
			errors = append(errors, err)
		} else {
			s.Addr = addr
			s.Endpoints = []*net.UDPAddr{addr}
		}
	} else {
		errors = append(errors, fmt.Errorf("addr or addrs is required"))
	}

	return errors
}
