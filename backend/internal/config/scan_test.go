package config

import "testing"

// 공급망 검사 자원 · 자동 검사(11/04 종합 판정)
func TestScanSettings(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.ScanAuto || c.ScanConcurrency != 1 || c.ScanQueue != 4 || c.ScanMemoryMB != 1024 || c.ScanCPUs != 2 {
		t.Fatalf("defaults: auto %v conc %d queue %d mem %d cpus %v", c.ScanAuto, c.ScanConcurrency, c.ScanQueue, c.ScanMemoryMB, c.ScanCPUs)
	}
	t.Setenv("SCAN_AUTO", "off")
	t.Setenv("SCAN_CONCURRENCY", "2")
	t.Setenv("SCAN_QUEUE", "8")
	t.Setenv("SCAN_MEMORY_MB", "768")
	t.Setenv("SCAN_CPUS", "1.5")
	if c, err = Load(); err != nil || c.ScanAuto || c.ScanConcurrency != 2 || c.ScanQueue != 8 || c.ScanMemoryMB != 768 || c.ScanCPUs != 1.5 {
		t.Fatalf("set: %+v %v", c, err)
	}
	t.Setenv("SCAN_AUTO", "on")
	if c, err = Load(); err != nil || !c.ScanAuto {
		t.Fatalf("on: %v %v", c.ScanAuto, err)
	}
	for k, bad := range map[string]string{"SCAN_AUTO": "maybe", "SCAN_CONCURRENCY": "0", "SCAN_QUEUE": "-1", "SCAN_MEMORY_MB": "64", "SCAN_CPUS": "0"} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, bad)
			if _, err := Load(); err == nil {
				t.Fatalf("%s=%s must be rejected", k, bad)
			}
		})
	}
}
