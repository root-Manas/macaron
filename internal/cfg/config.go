package cfg

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	APIKeys map[string]string `yaml:"api_keys"`
}

func Load(storageRoot string) (*Config, error) {
	cfg := &Config{APIKeys: map[string]string{}}
	path := filepath.Join(storageRoot, "config.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	if cfg.APIKeys == nil {
		cfg.APIKeys = map[string]string{}
	}
	return cfg, nil
}

func Save(storageRoot string, cfg *Config) error {
	if err := os.MkdirAll(storageRoot, 0o755); err != nil {
		return err
	}
	if cfg.APIKeys == nil {
		cfg.APIKeys = map[string]string{}
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(storageRoot, "config.yaml"), b, 0o644)
}

func ApplySetAPI(cfg *Config, kvs []string) {
	if cfg.APIKeys == nil {
		cfg.APIKeys = map[string]string{}
	}
	for _, kv := range kvs {
		parts := strings.SplitN(strings.TrimSpace(kv), "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(parts[0]))
		v := strings.TrimSpace(parts[1])
		if k == "" {
			continue
		}
		if v == "" {
			delete(cfg.APIKeys, k)
			continue
		}
		cfg.APIKeys[k] = v
	}
}

func MaskedKeys(cfg *Config) []string {
	keys := make([]string, 0, len(cfg.APIKeys))
	for k, v := range cfg.APIKeys {
		mask := "<empty>"
		if v != "" {
			if len(v) <= 6 {
				mask = "***"
			} else {
				mask = v[:3] + "***" + v[len(v)-3:]
			}
		}
		keys = append(keys, k+"="+mask)
	}
	sort.Strings(keys)
	return keys
}
