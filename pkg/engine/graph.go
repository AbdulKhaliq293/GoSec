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
	Nodes    map[string]*Node
	Edges    []Edge
	Findings []Finding
	mu       sync.RWMutex
}

// Node represents an asset in the infrastructure graph
type Node struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`     // host, service, container, attacker
	Label    string            `json:"label"`    // Human readable name
	Metadata map[string]string `json:"metadata"` // OS, version, etc.
}

// Edge represents a relationship between nodes
type Edge struct {
	SourceID string `json:"source_id"`
	TargetID string `json:"target_id"`
	Type     string `json:"type"` // connects_to, runs, exposes, credentials
	Weight   int    `json:"weight"`
}

// NewUnifiedGraph creates a new graph instance
func NewUnifiedGraph() *UnifiedGraph {
	return &UnifiedGraph{
		Nodes:    make(map[string]*Node),
		Edges:    make([]Edge, 0),
		Findings: make([]Finding, 0),
	}
}

// AddNode adds or updates a node in the graph
func (g *UnifiedGraph) AddNode(node Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Nodes[node.ID] = &node
}

// AddEdge adds a relationship between two nodes
func (g *UnifiedGraph) AddEdge(edge Edge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Edges = append(g.Edges, edge)
}

// AddFindings ingests new findings, normalizes them, deduplicates, and updates relationships
func (g *UnifiedGraph) AddFindings(newFindings []Finding) {
	g.mu.Lock()
	defer g.mu.Unlock()

	for _, f := range newFindings {
		// Step 1: Ensure Node exists for the Asset
		if f.Asset != "" {
			if _, exists := g.Nodes[f.Asset]; !exists {
				// Auto-create node from finding asset
				g.Nodes[f.Asset] = &Node{
					ID:    f.Asset,
					Type:  "host", // Default to host, can be refined later
					Label: f.Asset,
				}
			}
		}

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

// GraphSnapshot represents the serializable state of the graph
type GraphSnapshot struct {
	Nodes    map[string]*Node `json:"nodes"`
	Edges    []Edge           `json:"edges"`
	Findings []Finding        `json:"findings"`
}

// SaveSnapshot saves the current graph (Nodes, Edges, Findings) to a JSON file
func (g *UnifiedGraph) SaveSnapshot(path string) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	snapshot := GraphSnapshot{
		Nodes:    g.Nodes,
		Edges:    g.Edges,
		Findings: g.Findings,
	}

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadSnapshot loads the graph from a JSON file
func (g *UnifiedGraph) LoadSnapshot(path string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var snapshot GraphSnapshot
	// Try parsing as full snapshot
	if err := json.Unmarshal(data, &snapshot); err == nil && (len(snapshot.Nodes) > 0 || len(snapshot.Findings) > 0) {
		g.Nodes = snapshot.Nodes
		if g.Nodes == nil {
			g.Nodes = make(map[string]*Node)
		}
		g.Edges = snapshot.Edges
		if g.Edges == nil {
			g.Edges = make([]Edge, 0)
		}
		g.Findings = snapshot.Findings
		return nil
	}

	// Fallback: Try parsing as simple list of findings (Legacy format)
	var findings []Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return fmt.Errorf("failed to parse snapshot as GraphSnapshot or []Finding: %v", err)
	}

	g.Findings = findings
	// Note: Nodes and Edges will be empty for legacy snapshots unless we rebuild them
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
