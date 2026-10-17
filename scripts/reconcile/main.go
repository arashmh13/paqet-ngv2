package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/arashmh13/paqet-ngv2/internal/ng/dns"
)

func main() {
	filePath := "docs/research/emergency_dns_hardened_soak_stats.json"
	if len(os.Args) > 1 {
		filePath = os.Args[1]
	}

	report, err := dns.LoadAndReconcileBenchmarkFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshal error: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(filePath, out, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Write file error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully reconciled %s using %s\n", filePath, report.StatisticalMethod)
}
