package engine

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Control represents a single compliance check
type Control struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	CheckTool   string `yaml:"check_tool"` // e.g., "nmap", "lynis", "script"
	Command     string `yaml:"command"`
	Remediation string `yaml:"remediation"`
}

// Profile represents a compliance standard (e.g., HIPAA)
type Profile struct {
	Standard    string    `yaml:"standard"`
	Description string    `yaml:"description"`
	Controls    []Control `yaml:"controls"`
}

// Engine manages compliance profiles
type Engine struct {
	Profiles map[string]Profile
}

// NewEngine creates a new compliance engine
func NewEngine() *Engine {
	return &Engine{
		Profiles: make(map[string]Profile),
	}
}

// LoadProfiles reads YAML profiles from a directory
func (e *Engine) LoadProfiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() && (filepath.Ext(entry.Name()) == ".yaml" || filepath.Ext(entry.Name()) == ".yml") {
			path := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			var p Profile
			if err := yaml.Unmarshal(data, &p); err != nil {
				return fmt.Errorf("failed to parse %s: %v", entry.Name(), err)
			}
			e.Profiles[p.Standard] = p
			fmt.Printf("Loaded compliance profile: %s\n", p.Standard)
		}
	}
	return nil
}

// ListStandards returns the names of loaded standards
func (e *Engine) ListStandards() []string {
	keys := make([]string, 0, len(e.Profiles))
	for k := range e.Profiles {
		keys = append(keys, k)
	}
	return keys
}

// GetProfile retrieves a profile by name
func (e *Engine) GetProfile(name string) (Profile, bool) {
	p, ok := e.Profiles[name]
	return p, ok
}
