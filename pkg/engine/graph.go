package engine

import (
	"fmt"
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
