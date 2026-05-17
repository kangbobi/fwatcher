package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Paths            []string `yaml:"paths"`
	Recursive        bool     `yaml:"recursive"`
	LogPath          string   `yaml:"log_path"`
	HashFiles        bool     `yaml:"hash_files"`
	MaxHashSizeMB    int64    `yaml:"max_hash_size_mb"`
	IgnorePatterns   []string `yaml:"ignore_patterns"`
	DebounceMs       int      `yaml:"debounce_ms"`
	MaxDiffSizeKB    int64    `yaml:"max_diff_size_kb"`    // 0 disables content diffing
	DiffContextLines int      `yaml:"diff_context_lines"`  // unified diff context
	MaxDiffOutputKB  int      `yaml:"max_diff_output_kb"`  // cap diff field in JSON log
	DetectEditor     *bool    `yaml:"detect_editor"`       // nil → default true
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if len(c.Paths) == 0 {
		return nil, fmt.Errorf("config: 'paths' is required and must be non-empty")
	}
	if c.LogPath == "" {
		c.LogPath = "fwatcher.json"
	}
	if c.MaxHashSizeMB == 0 {
		c.MaxHashSizeMB = 100
	}
	if c.DebounceMs == 0 {
		c.DebounceMs = 300
	}
	if c.DiffContextLines == 0 {
		c.DiffContextLines = 3
	}
	if c.MaxDiffOutputKB == 0 {
		c.MaxDiffOutputKB = 16
	}
	// MaxDiffSizeKB default is 0 (disabled) — user must opt in by setting it.
	if c.DetectEditor == nil {
		t := true
		c.DetectEditor = &t
	}
	return &c, nil
}
