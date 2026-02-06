package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type ProviderConfig struct {
	APIKey string `yaml:"api_key"`
}

type Config struct {
	SelectedProvider string                    `yaml:"selected_provider"`
	SelectedModel    string                    `yaml:"selected_model"`
	Providers        map[string]ProviderConfig `yaml:"providers"`
}

func GetConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	configDir := filepath.Join(home, ".gosec-adk")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(configDir, "config.yaml"), nil
}

func LoadConfig() (*Config, error) {
	path, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// Return default config
		return &Config{
			SelectedProvider: "gemini",
			SelectedModel:    "gemini-pro",
			Providers:        make(map[string]ProviderConfig),
		}, nil
	}
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Providers == nil {
		cfg.Providers = make(map[string]ProviderConfig)
	}
	return &cfg, nil
}

func SaveConfig(cfg *Config) error {
	path, err := GetConfigPath()
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	// 0600 permissions for security (api keys)
	return os.WriteFile(path, data, 0600)
}

func (c *Config) SetAPIKey(provider, key string) {
	p := c.Providers[provider]
	p.APIKey = key
	c.Providers[provider] = p
}

func (c *Config) GetAPIKey(provider string) string {
	return c.Providers[provider].APIKey
}
