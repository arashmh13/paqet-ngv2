package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/arashmh13/paqet-ngv2/internal/conf"
	"github.com/arashmh13/paqet-ngv2/internal/server"
)

func parseKeyBytes(rawStr string) ([]byte, error) {
	rawStr = strings.TrimSpace(rawStr)
	if b, err := base64.StdEncoding.DecodeString(rawStr); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := hex.DecodeString(rawStr); err == nil && len(b) == 32 {
		return b, nil
	}
	if len(rawStr) == 32 {
		return []byte(rawStr), nil
	}
	return nil, fmt.Errorf("invalid key length %d: must decode to 32 bytes", len(rawStr))
}

func main() {
	primaryPort := flag.Int("primary-port", 18088, "Primary test Paqet server port")
	candidatePort := flag.Int("candidate-port", 18089, "Candidate test Paqet server port")
	originPort := flag.Int("origin-port", 18999, "HTTP test origin port")
	keyFile := flag.String("key-file", "/opt/paqet/emergency.key", "Path to emergency key file")
	tokenFile := flag.String("token-file", "/opt/paqet/current_test_token.txt", "Path to test token file")
	flag.Parse()

	keyBytes, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatalf("Read key file: %v", err)
	}
	psk, err := parseKeyBytes(string(keyBytes))
	if err != nil {
		log.Fatalf("Parse key: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// 1. HTTP Test Origin on 127.0.0.1:originPort
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/test-token", func(w http.ResponseWriter, r *http.Request) {
		tokenBytes, _ := os.ReadFile(*tokenFile)
		token := strings.TrimSpace(string(tokenBytes))
		log.Printf("[HTTP-ORIGIN] Received request from %s -> returning token %s", r.RemoteAddr, token)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "RECOVERY_VERIFIED",
			"token":  token,
		})
	})
	originServer := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", *originPort),
		Handler: httpMux,
	}
	originLn, err := net.Listen("tcp", originServer.Addr)
	if err != nil {
		log.Fatalf("Listen origin HTTP: %v", err)
	}
	defer originLn.Close()
	go func() { _ = originServer.Serve(originLn) }()
	log.Printf("[ORIGIN] HTTP test origin listening on %s", originServer.Addr)

	// 2. Primary Paqet Server (:18088)
	primaryUDP, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", *primaryPort))
	primaryCfg := &conf.Conf{
		Role: "server",
		Listen: conf.Server{
			Addr:      primaryUDP,
			Endpoints: []*net.UDPAddr{primaryUDP},
		},
		Transport: conf.Transport{
			Protocol: "aead-stream",
			Obfs: &conf.Obfs{
				Enabled: true,
				Key:     string(psk),
				MaxPad:  64,
			},
		},
	}
	primarySrv, err := server.New(primaryCfg)
	if err != nil {
		log.Fatalf("Primary server.New: %v", err)
	}
	if err := primarySrv.Start(ctx); err != nil {
		log.Fatalf("Primary server.Start: %v", err)
	}
	log.Printf("[PRIMARY] Paqet primary server listening on :%d (aead-stream)", *primaryPort)

	// 3. Candidate Paqet Server (:18089)
	candidateUDP, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", *candidatePort))
	candidateCfg := &conf.Conf{
		Role: "server",
		Listen: conf.Server{
			Addr:      candidateUDP,
			Endpoints: []*net.UDPAddr{candidateUDP},
		},
		Transport: conf.Transport{
			Protocol: "aead-stream",
			Obfs: &conf.Obfs{
				Enabled: true,
				Key:     string(psk),
				MaxPad:  64,
			},
		},
	}
	candidateSrv, err := server.New(candidateCfg)
	if err != nil {
		log.Fatalf("Candidate server.New: %v", err)
	}
	if err := candidateSrv.Start(ctx); err != nil {
		log.Fatalf("Candidate server.Start: %v", err)
	}
	log.Printf("[CANDIDATE] Paqet candidate server listening on :%d (aead-stream)", *candidatePort)

	<-ctx.Done()
	log.Printf("Shutting down test servers...")
}
