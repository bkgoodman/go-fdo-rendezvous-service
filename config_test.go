// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.Server.Addr != "localhost:8080" {
		t.Errorf("expected default addr localhost:8080, got %s", c.Server.Addr)
	}
	if c.Auth.Mode != "open" {
		t.Errorf("expected default auth mode open, got %s", c.Auth.Mode)
	}
	if c.RV.ReplacementPolicy != "allow-any" {
		t.Errorf("expected default replacement policy allow-any, got %s", c.RV.ReplacementPolicy)
	}
	if c.RV.MaxTTL != 4294967295 {
		t.Errorf("expected default max_ttl 4294967295, got %d", c.RV.MaxTTL)
	}
	if c.DID.RefreshHours != 24 {
		t.Errorf("expected default refresh_hours 24, got %d", c.DID.RefreshHours)
	}
	if c.Pruning.InactiveHours != 720 {
		t.Errorf("expected default inactive_hours 720, got %d", c.Pruning.InactiveHours)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	// Non-existent file should return defaults
	c, err := LoadConfig("/tmp/nonexistent-fdo-rv-test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth.Mode != "open" {
		t.Errorf("expected open, got %s", c.Auth.Mode)
	}
}

func TestLoadConfig_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	err := os.WriteFile(path, []byte(`
debug: true
server:
  addr: "0.0.0.0:9090"
auth:
  mode: "token"
rv:
  replacement_policy: "first-lock"
  max_ttl: 86400
did:
  refresh_hours: 12
pruning:
  enabled: true
  inactive_hours: 48
  interval_minutes: 30
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if !c.Debug {
		t.Error("expected debug true")
	}
	if c.Server.Addr != "0.0.0.0:9090" {
		t.Errorf("expected 0.0.0.0:9090, got %s", c.Server.Addr)
	}
	if c.Auth.Mode != "token" {
		t.Errorf("expected token, got %s", c.Auth.Mode)
	}
	if c.RV.ReplacementPolicy != "first-lock" {
		t.Errorf("expected first-lock, got %s", c.RV.ReplacementPolicy)
	}
	if c.RV.MaxTTL != 86400 {
		t.Errorf("expected 86400, got %d", c.RV.MaxTTL)
	}
	if c.DID.RefreshHours != 12 {
		t.Errorf("expected 12, got %d", c.DID.RefreshHours)
	}
	if !c.Pruning.Enabled {
		t.Error("expected pruning enabled")
	}
	if c.Pruning.InactiveHours != 48 {
		t.Errorf("expected 48, got %d", c.Pruning.InactiveHours)
	}
}

func TestLoadConfig_InvalidAuthMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte(`auth: { mode: "invalid" }`), 0644)

	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid auth mode")
	}
}

func TestLoadConfig_InvalidReplacementPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte(`rv: { replacement_policy: "invalid" }`), 0644)

	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid replacement policy")
	}
}

func TestConfig_PruningInterval(t *testing.T) {
	c := DefaultConfig()
	c.Pruning.IntervalMinutes = 30
	if c.PruningInterval() != 30*time.Minute {
		t.Errorf("expected 30m, got %s", c.PruningInterval())
	}
}

func TestConfig_DIDRefreshThreshold(t *testing.T) {
	c := DefaultConfig()
	if c.DIDRefreshThreshold() != 24*time.Hour {
		t.Errorf("expected 24h, got %s", c.DIDRefreshThreshold())
	}
}
