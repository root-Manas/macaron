package cfg

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds macaron's persistent settings.
type Config struct {
	APIKeys map[string]string `yaml:"api_keys"`
}

// Load reads config from storageRoot/config.yaml. Missing file returns empty config.
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

// Save writes config to storageRoot/config.yaml.
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

// ApplySetAPI merges key=value pairs into config. Empty value removes the key.
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

// BulkLoadFile reads a YAML file of the form `api_keys: {key: value}` and
// merges its contents into cfg. It also accepts a flat map[string]string.
func BulkLoadFile(cfg *Config, path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	// Try structured Config format first.
	var bulk Config
	if err := yaml.Unmarshal(b, &bulk); err == nil && len(bulk.APIKeys) > 0 {
		if cfg.APIKeys == nil {
			cfg.APIKeys = map[string]string{}
		}
		for k, v := range bulk.APIKeys {
			k = strings.ToLower(strings.TrimSpace(k))
			if k != "" && strings.TrimSpace(v) != "" {
				cfg.APIKeys[k] = strings.TrimSpace(v)
			}
		}
		return len(bulk.APIKeys), nil
	}
	// Try flat map.
	var flat map[string]string
	if err := yaml.Unmarshal(b, &flat); err == nil && len(flat) > 0 {
		if cfg.APIKeys == nil {
			cfg.APIKeys = map[string]string{}
		}
		count := 0
		for k, v := range flat {
			k = strings.ToLower(strings.TrimSpace(k))
			if k != "" && strings.TrimSpace(v) != "" {
				cfg.APIKeys[k] = strings.TrimSpace(v)
				count++
			}
		}
		return count, nil
	}
	return 0, fmt.Errorf("no api_keys found in %s", path)
}

// ImportFromTools scans well-known tool config locations and imports any API
// keys found there into cfg. Returns a summary of what was imported.
func ImportFromTools(cfg *Config) []string {
	if cfg.APIKeys == nil {
		cfg.APIKeys = map[string]string{}
	}
	var imported []string

	// subfinder: ~/.config/subfinder/provider-config.yaml
	// format: provider:\n  - KEY
	if keys := readSubfinderConfig(); len(keys) > 0 {
		for k, v := range keys {
			if _, exists := cfg.APIKeys[k]; !exists {
				cfg.APIKeys[k] = v
				imported = append(imported, fmt.Sprintf("subfinder → %s", k))
			}
		}
	}

	// amass: ~/.config/amass/config.yaml / config.ini
	if keys := readAmassConfig(); len(keys) > 0 {
		for k, v := range keys {
			if _, exists := cfg.APIKeys[k]; !exists {
				cfg.APIKeys[k] = v
				imported = append(imported, fmt.Sprintf("amass → %s", k))
			}
		}
	}

	sort.Strings(imported)
	return imported
}

// WriteSubfinderProviderConfig writes macaron's API keys in subfinder's
// provider-config.yaml format to the given path, so subfinder picks them up.
func WriteSubfinderProviderConfig(cfg *Config, path string) error {
	// Map macaron key names → subfinder provider names.
	providerMap := map[string]string{
		"securitytrails":   "securitytrails",
		"virustotal":       "virustotal",
		"shodan":           "shodan",
		"censys_id":        "censys",
		"censys_secret":    "censys",
		"binaryedge":       "binaryedge",
		"c99":              "c99",
		"chaos":            "chaos",
		"hunter":           "hunter",
		"intelx":           "intelx",
		"passivetotal_key": "passivetotal",
		"passivetotal_usr": "passivetotal",
		"recon_dev":        "recon",
		"robtex":           "robtex",
		"urlscan":          "urlscan",
		"zoomeye":          "zoomeye",
		"fullhunt":         "fullhunt",
		"github":           "github",
		"leakix":           "leakix",
		"netlas":           "netlas",
		"fofa_email":       "fofa",
		"fofa_key":         "fofa",
		"quake":            "quake",
		"hunterhow":        "hunterhow",
	}

	// Build provider → []key map.
	providers := map[string][]string{}
	for macaronKey, providerName := range providerMap {
		v, ok := cfg.APIKeys[macaronKey]
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		providers[providerName] = append(providers[providerName], v)
	}

	if len(providers) == 0 {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	b, err := yaml.Marshal(providers)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// MaskedKeys returns sorted key=masked-value strings for display.
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

// ─── internal helpers ────────────────────────────────────────────────────────

func readSubfinderConfig() map[string]string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	path := filepath.Join(home, ".config", "subfinder", "provider-config.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw map[string][]string
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil
	}
	out := make(map[string]string, len(raw))
	for provider, keys := range raw {
		if len(keys) > 0 && strings.TrimSpace(keys[0]) != "" {
			out[strings.ToLower(provider)] = strings.TrimSpace(keys[0])
		}
	}
	return out
}

func readAmassConfig() map[string]string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	// amass stores keys in config.yaml under `data_sources`
	for _, candidate := range []string{
		filepath.Join(home, ".config", "amass", "config.yaml"),
		filepath.Join(home, ".config", "amass", "config.ini"),
	} {
		b, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		// Best-effort: look for api_key or apikey patterns.
		var raw map[string]any
		if err := yaml.Unmarshal(b, &raw); err != nil {
			continue
		}
		out := flattenAPIKeys(raw)
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// flattenAPIKeys recursively extracts API keys from an arbitrary config map.
// For string leaf values, it includes entries whose key name contains "key"
// or "token". For nested map[string]any values, it recurses and prefixes
// child key names with the parent key joined by "_"
// (e.g. parent "virustotal" + child "key" → "virustotal_key").
func flattenAPIKeys(m map[string]any) map[string]string {
	out := make(map[string]string)
	for k, v := range m {
		switch val := v.(type) {
		case string:
			lk := strings.ToLower(k)
			if strings.Contains(lk, "key") || strings.Contains(lk, "token") {
				if strings.TrimSpace(val) != "" {
					out[strings.ToLower(k)] = strings.TrimSpace(val)
				}
			}
		case map[string]any:
			for kk, vv := range flattenAPIKeys(val) {
				out[k+"_"+kk] = vv
			}
		}
	}
	return out
}
