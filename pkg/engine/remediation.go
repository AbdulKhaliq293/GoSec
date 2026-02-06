package engine

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// RemediationTemplate represents a remediation script template
type RemediationTemplate struct {
	ID                string   `yaml:"id"`
	Name              string   `yaml:"name"`
	Issue             string   `yaml:"issue"`
	Risk              string   `yaml:"risk"`
	Standard          string   `yaml:"standard"`
	Description       string   `yaml:"description"`
	FixCommand        string   `yaml:"fix_command"`
	ValidationCommand string   `yaml:"validation_command"`
	RollbackCommand   string   `yaml:"rollback_command"`
	Variables         []string `yaml:"variables"`
}

// RemediationEngine manages remediation templates
type RemediationEngine struct {
	Templates map[string]RemediationTemplate
}

// NewRemediationEngine creates a new remediation engine
func NewRemediationEngine() *RemediationEngine {
	return &RemediationEngine{
		Templates: make(map[string]RemediationTemplate),
	}
}

// LoadTemplates reads YAML templates from a directory
func (e *RemediationEngine) LoadTemplates(dir string) error {
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

			var t RemediationTemplate
			if err := yaml.Unmarshal(data, &t); err != nil {
				return fmt.Errorf("failed to parse %s: %v", entry.Name(), err)
			}
			e.Templates[t.ID] = t
			fmt.Printf("Loaded remediation template: %s\n", t.ID)
		}
	}
	return nil
}

// ListTemplates returns a list of available template IDs and descriptions
func (e *RemediationEngine) ListTemplates() []string {
	var list []string
	for _, t := range e.Templates {
		list = append(list, fmt.Sprintf("%s: %s", t.ID, t.Name))
	}
	return list
}

// GeneratePlan creates a remediation plan from a template and variables
func (e *RemediationEngine) GeneratePlan(id string, vars map[string]string) (string, error) {
	tmpl, ok := e.Templates[id]
	if !ok {
		return "", fmt.Errorf("template not found: %s", id)
	}

	// Validate required variables
	for _, requiredVar := range tmpl.Variables {
		if _, exists := vars[requiredVar]; !exists {
			return "", fmt.Errorf("missing required variable: %s", requiredVar)
		}
	}

	// Render Fix Command
	fixCmd, err := renderString("fix", tmpl.FixCommand, vars)
	if err != nil {
		return "", err
	}

	// Render Validation Command
	validateCmd, err := renderString("validate", tmpl.ValidationCommand, vars)
	if err != nil {
		return "", err
	}

	// Render Rollback Command
	rollbackCmd, err := renderString("rollback", tmpl.RollbackCommand, vars)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString("[FIX PLAN]\n")
	sb.WriteString(fmt.Sprintf("Issue: %s\n", tmpl.Issue))
	sb.WriteString(fmt.Sprintf("Risk: %s\n", tmpl.Risk))
	sb.WriteString(fmt.Sprintf("Standard: %s\n\n", tmpl.Standard))
	
	sb.WriteString("Suggested Fix:\n")
	sb.WriteString(fixCmd + "\n\n")
	
	sb.WriteString("Validation:\n")
	sb.WriteString(validateCmd + "\n\n")
	
	sb.WriteString("Rollback:\n")
	sb.WriteString(rollbackCmd + "\n")

	return sb.String(), nil
}

func renderString(name, tmplStr string, vars map[string]string) (string, error) {
	t, err := template.New(name).Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template %s: %v", name, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, vars); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %v", name, err)
	}
	return buf.String(), nil
}
