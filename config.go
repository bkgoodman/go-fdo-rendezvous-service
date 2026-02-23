// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the rendezvous server configuration.
type Config struct {
	Debug bool `yaml:"debug"`

	Server struct {
		Addr    string `yaml:"addr"`
		ExtAddr string `yaml:"ext_addr"`
		UseTLS  bool   `yaml:"use_tls"`
	} `yaml:"server"`

	Database struct {
		Path     string `yaml:"path"`
		Password string `yaml:"password"`
	} `yaml:"database"`

	Auth struct {
		Mode string `yaml:"mode"` // "open", "token", "signatory"
	} `yaml:"auth"`

	RV struct {
		ReplacementPolicy string `yaml:"replacement_policy"` // "allow-any", "mfg-consistency", "first-lock", "owner-consistency"
		MaxTTL            uint32 `yaml:"max_ttl"`
	} `yaml:"rv"`

	DID struct {
		RefreshHours int  `yaml:"refresh_hours"` // Lazy refresh threshold for DID:web keys
		InsecureHTTP bool `yaml:"insecure_http"` // Allow HTTP for DID:web (dev/test only)
	} `yaml:"did"`

	Pruning struct {
		Enabled         bool `yaml:"enabled"`
		InactiveHours   int  `yaml:"inactive_hours"`
		IntervalMinutes int  `yaml:"interval_minutes"`
	} `yaml:"pruning"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	c := &Config{}
	c.Debug = false
	c.Server.Addr = "localhost:8080"
	c.Server.ExtAddr = ""
	c.Server.UseTLS = false
	c.Database.Path = "rendezvous.db"
	c.Database.Password = ""
	c.Auth.Mode = "open"
	c.RV.ReplacementPolicy = "allow-any"
	c.RV.MaxTTL = 4294967295
	c.DID.RefreshHours = 24
	c.DID.InsecureHTTP = false
	c.Pruning.Enabled = false
	c.Pruning.InactiveHours = 720 // 30 days
	c.Pruning.IntervalMinutes = 60
	return c
}

// LoadConfig loads configuration from a YAML file, applying defaults first.
func LoadConfig(path string) (*Config, error) {
	config := DefaultConfig()

	if path == "" {
		return config, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil
		}
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return config, nil
}

// Validate checks that config values are within acceptable ranges.
func (c *Config) Validate() error {
	switch c.Auth.Mode {
	case "open", "token", "signatory":
	default:
		return fmt.Errorf("auth.mode must be open, token, or signatory; got %q", c.Auth.Mode)
	}

	switch c.RV.ReplacementPolicy {
	case "allow-any", "mfg-consistency", "first-lock", "owner-consistency":
	default:
		return fmt.Errorf("rv.replacement_policy must be allow-any, mfg-consistency, first-lock, or owner-consistency; got %q", c.RV.ReplacementPolicy)
	}

	if c.RV.MaxTTL == 0 {
		return fmt.Errorf("rv.max_ttl must be > 0")
	}

	if c.Pruning.Enabled {
		if c.Pruning.InactiveHours <= 0 {
			return fmt.Errorf("pruning.inactive_hours must be > 0 when pruning is enabled")
		}
		if c.Pruning.IntervalMinutes <= 0 {
			return fmt.Errorf("pruning.interval_minutes must be > 0 when pruning is enabled")
		}
	}

	return nil
}

// PruningInterval returns the pruning interval as a time.Duration.
func (c *Config) PruningInterval() time.Duration {
	return time.Duration(c.Pruning.IntervalMinutes) * time.Minute
}

// DIDRefreshThreshold returns the DID refresh threshold as a time.Duration.
func (c *Config) DIDRefreshThreshold() time.Duration {
	return time.Duration(c.DID.RefreshHours) * time.Hour
}
