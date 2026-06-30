// Package config loads the git-proxy YAML configuration.
//
// The configuration carries the proxy listen address, the upstream git server
// URL, and a repo map that translates a repository path as seen by the agent
// into the repository path served by the upstream.
//
// Example:
//
//	listen: "127.0.0.1:8080"
//	upstream:
//	  url: "http://git.example.com"
//	repos:
//	  "team/repo.git": "team/repo.git"
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the parsed proxy configuration.
type Config struct {
	Listen   string         `yaml:"listen"`
	Upstream UpstreamConfig `yaml:"upstream"`
	Repos    map[string]string `yaml:"repos"`
}

// UpstreamConfig describes the upstream git server the proxy forwards to.
type UpstreamConfig struct {
	URL string `yaml:"url"`
}

// Parse decodes configuration from raw YAML bytes.
func Parse(b []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Load reads and parses the configuration file at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return Parse(b)
}

// validate enforces required fields. Security-relevant config defaults to deny:
// a missing listen address or upstream URL is a configuration error, not a
// silent default.
func (c *Config) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("config: listen is required")
	}
	if c.Upstream.URL == "" {
		return fmt.Errorf("config: upstream.url is required")
	}
	return nil
}

// RepoPath maps an agent-facing repository path to the upstream repository
// path. If the repo is not in the map, the agent-facing path is used verbatim
// (passthrough). Later milestones may fail closed on unknown repos; passthrough
// does not.
func (c *Config) RepoPath(repo string) string {
	if p, ok := c.Repos[repo]; ok && p != "" {
		return p
	}
	return repo
}