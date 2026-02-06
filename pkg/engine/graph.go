package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// UnifiedGraph holds the normalized findings and manages relationships
type UnifiedGraph struct {
	Findings []Finding
	mu       sync.RWMutex
}

// NewUnifiedGraph creates a new graph instance
func NewUnifiedGraph() *UnifiedGraph {
	return &UnifiedGraph{
		Findings: make([]Finding, 0),
	}
}

// AddFindings ingests new findings, normalizes them, deduplicates, and updates relationships
func (g *UnifiedGraph) AddFindings(newFindings []Finding) {
	g.mu.Lock()
	defer g.mu.Unlock()

	for _, f := range newFindings {
		// Step 2: Severity Normalization (if not already set or needs adjustment)
		// Note: Normalizers should ideally set this, but we can enforce rules here
		// Example rules could go here if global normalization was needed.
		// Since the prompt asks for specific mapping, we assume the Normalizers (Wrappers)
		// doing the initial mapping, but we can enforce limits here.
		if f.Severity < 1 {
			f.Severity = 1
		}
		if f.Severity > 10 {
			f.Severity = 10
		}

		// Step 3: Deduplication Logic
		// Check if finding already exists (Same Asset + Same Category + Similar Evidence)
		// Or simpler: Same ID if we generate deterministic IDs.
		// If ID is not deterministic, we compare fields.
		exists := false
		for i, existing := range g.Findings {
			if existing.Asset == f.Asset && existing.Category == f.Category && existing.SourceTool == f.SourceTool && existing.Evidence == f.Evidence {
				// Update existing finding if needed (e.g. timestamp, or higher severity)
				g.Findings[i] = f // Overwrite with latest
				exists = true
				break
			}
		}

		if !exists {
			g.Findings = append(g.Findings, f)
		}
	}

	// Step 4: Relationship Detection
	g.detectRelationships()
}

// detectRelationships escalates severity based on combinations of findings
func (g *UnifiedGraph) detectRelationships() {
	// Example: Open SSH (Nmap) + Weak Crypto Policy (Lynis/Compliance) -> Escalate
	
	hasOpenSSH := false
	var sshFindingIndex int

	// Scan for Open SSH
	for i, f := range g.Findings {
		if f.SourceTool == "Nmap" && strings.Contains(f.Evidence, "22/tcp") && strings.Contains(f.Evidence, "open") {
			hasOpenSSH = true
			sshFindingIndex = i
		}
	}

	// Scan for Weak Crypto (Simulated for now, or based on Lynis warnings)
	hasWeakCrypto := false
	for _, f := range g.Findings {
		if f.SourceTool == "Lynis" && strings.Contains(strings.ToLower(f.Evidence), "crypto") {
			// This is a heuristic example
			hasWeakCrypto = true
		}
	}

	if hasOpenSSH && hasWeakCrypto {
		// Escalate SSH finding severity
		if g.Findings[sshFindingIndex].Severity < 10 {
			g.Findings[sshFindingIndex].Severity += 2 // Boost severity
			if g.Findings[sshFindingIndex].Severity > 10 {
				g.Findings[sshFindingIndex].Severity = 10
			}
			g.Findings[sshFindingIndex].RemediationHint += " [CRITICAL: Combined with Weak Crypto Policy]"
		}
	}
}

// GenerateSignature creates a unique string for a finding to track identity across scans
func GenerateSignature(f Finding) string {
	// If ID is present and looks like a UUID or Hash, use it?
	// But AddFindings uses Asset+Category+SourceTool+Evidence. We should stick to that for consistency.
	return fmt.Sprintf("%s|%s|%s|%s", f.SourceTool, f.Category, f.Asset, f.Evidence)
}

// SaveSnapshot saves the current graph findings to a JSON file
func (g *UnifiedGraph) SaveSnapshot(path string) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	data, err := json.MarshalIndent(g.Findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadSnapshot loads findings from a JSON file into the graph
func (g *UnifiedGraph) LoadSnapshot(path string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var findings []Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return err
	}

	g.Findings = findings
	return nil
}

// SnapshotDiff represents the difference between two scans
type SnapshotDiff struct {
	New       []Finding
	Fixed     []Finding
	Unchanged []Finding
}

// CompareSnapshot compares the current graph against a baseline graph
func (g *UnifiedGraph) CompareSnapshot(baseline *UnifiedGraph) SnapshotDiff {
	g.mu.RLock()
	defer g.mu.RUnlock()
	// baseline.mu.RLock() // Assuming baseline is static/loaded, but good practice
	// defer baseline.mu.RUnlock()

	diff := SnapshotDiff{
		New:       make([]Finding, 0),
		Fixed:     make([]Finding, 0),
		Unchanged: make([]Finding, 0),
	}

	// Map baseline signatures
	baselineMap := make(map[string]Finding)
	for _, f := range baseline.Findings {
		sig := GenerateSignature(f)
		baselineMap[sig] = f
	}

	// Map current signatures
	currentMap := make(map[string]Finding)
	for _, f := range g.Findings {
		sig := GenerateSignature(f)
		currentMap[sig] = f

		if _, exists := baselineMap[sig]; exists {
			diff.Unchanged = append(diff.Unchanged, f)
		} else {
			diff.New = append(diff.New, f)
		}
	}

	// Find Fixed (in baseline but not in current)
	for sig, f := range baselineMap {
		if _, exists := currentMap[sig]; !exists {
			diff.Fixed = append(diff.Fixed, f)
		}
	}

	return diff
}

// GetReport returns a text summary of the graph
func (g *UnifiedGraph) GetReport() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Unified Finding Graph (%d findings):\n", len(g.Findings)))
	sb.WriteString("--------------------------------------------------\n")
	
	for _, f := range g.Findings {
		sb.WriteString(fmt.Sprintf("[%d/10] %s (%s)\n", f.Severity, f.Category, f.SourceTool))
		sb.WriteString(fmt.Sprintf("  Asset: %s\n", f.Asset))
		sb.WriteString(fmt.Sprintf("  Evidence: %s\n", f.Evidence))
		if f.RemediationHint != "" {
			sb.WriteString(fmt.Sprintf("  Fix: %s\n", f.RemediationHint))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
