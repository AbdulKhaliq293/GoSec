package engine

import (
	"fmt"
	"strings"
)

// AttackPath represents a valid breach path
type AttackPath struct {
	Steps []PathStep
	Score int
}

type PathStep struct {
	NodeID      string
	EdgeType    string // The action taken to get here
	Description string
}

// AttackPathEngine analyzes the graph for attack paths
type AttackPathEngine struct {
	Graph *UnifiedGraph
}

// NewAttackPathEngine creates a new engine
func NewAttackPathEngine(g *UnifiedGraph) *AttackPathEngine {
	return &AttackPathEngine{Graph: g}
}

// FindPathsToCriticalAssets finds paths from Attacker to any node with Critical/High findings
func (ape *AttackPathEngine) FindPathsToCriticalAssets() []AttackPath {
	ape.Graph.mu.RLock()
	defer ape.Graph.mu.RUnlock()

	var paths []AttackPath

	// 1. Identify Start Node
	startNodeID := "attacker"
	if _, ok := ape.Graph.Nodes[startNodeID]; !ok {
		// If no explicit attacker, try to find an external IP or entry point
		// For now, return empty if no attacker node found (must be populated by Nmap wrapper)
		return nil
	}

	// 2. Identify Targets (Nodes with Critical/High Findings)
	targets := make(map[string]bool)
	for _, f := range ape.Graph.Findings {
		if f.Severity >= 7 { // High/Critical threshold
			// If finding is attached to a node, that node is a target
			if _, ok := ape.Graph.Nodes[f.Asset]; ok {
				targets[f.Asset] = true
			}
		}
	}

	// 3. BFS to find paths
	for targetID := range targets {
		if targetID == startNodeID {
			continue
		}
		path := ape.findPath(startNodeID, targetID)
		if path != nil {
			paths = append(paths, *path)
		}
	}

	return paths
}

func (ape *AttackPathEngine) findPath(start, end string) *AttackPath {
	// Simple BFS
	queue := [][]string{{start}}
	visited := make(map[string]bool)
	visited[start] = true

	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]

		node := path[len(path)-1]

		if node == end {
			return ape.buildAttackPath(path)
		}

		// Find neighbors
		for _, edge := range ape.Graph.Edges {
			if edge.SourceID == node {
				if !visited[edge.TargetID] {
					visited[edge.TargetID] = true
					newPath := make([]string, len(path))
					copy(newPath, path)
					newPath = append(newPath, edge.TargetID)
					queue = append(queue, newPath)
				}
			}
		}
	}
	return nil
}

func (ape *AttackPathEngine) buildAttackPath(nodeIDs []string) *AttackPath {
	var steps []PathStep
	for i, id := range nodeIDs {
		step := PathStep{NodeID: id}

		// Find edge that got us here (except for start)
		if i > 0 {
			prev := nodeIDs[i-1]
			for _, edge := range ape.Graph.Edges {
				if edge.SourceID == prev && edge.TargetID == id {
					step.EdgeType = edge.Type
					step.Description = fmt.Sprintf("exploits %s", edge.Type)
					break
				}
			}
		} else {
			step.Description = "Start"
		}

		// Add info about the node
		node := ape.Graph.Nodes[id]
		if node != nil {
			if node.Label != "" {
				step.Description += fmt.Sprintf(" -> [%s] (%s)", node.Label, node.Type)
			} else {
				step.Description += fmt.Sprintf(" -> [%s] (%s)", node.ID, node.Type)
			}
		}

		steps = append(steps, step)
	}
	return &AttackPath{Steps: steps}
}

// GenerateStory returns a human-readable narrative
func (ap *AttackPath) GenerateStory() string {
	var sb strings.Builder
	sb.WriteString("🚨 **Attack Path Detected** 🚨\n")
	sb.WriteString("--------------------------------------------------\n")
	for i, step := range ap.Steps {
		if i == 0 {
			sb.WriteString(fmt.Sprintf("1. 🕵️  **Attacker** starts at %s\n", step.NodeID))
		} else {
			sb.WriteString(fmt.Sprintf("%d. ➡️  Moves to **%s** via %s\n", i+1, step.NodeID, step.EdgeType))
			// Extract context from description (simplified)
			if strings.Contains(step.Description, "(") {
				// sb.WriteString(fmt.Sprintf("    Context: %s\n", step.Description))
			}
		}
	}
	sb.WriteString("--------------------------------------------------\n")
	sb.WriteString("🎯 **Reachability to Critical Asset Confirmed**\n")
	return sb.String()
}
