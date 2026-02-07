package wrappers

import (
	"context"

	"github.com/user/gosec-adk/pkg/engine"
)

// GraphViewerWrapper implements the Tool interface for viewing the Unified Finding Graph
type GraphViewerWrapper struct{
	Graph *engine.UnifiedGraph
}

func (g *GraphViewerWrapper) Name() string {
	return "ShowUnifiedFindings"
}

func (g *GraphViewerWrapper) Description() string {
	return "Displays the Unified Finding Graph, showing all normalized security findings, severity scores, and detected relationships."
}

func (g *GraphViewerWrapper) Schema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{},
	}
}

func (g *GraphViewerWrapper) Execute(ctx context.Context, args map[string]interface{}, progress func(string)) (string, error) {
	if g.Graph == nil {
		return "Error: Unified Graph not initialized.", nil
	}

	report := g.Graph.GetReport()

	// Run Attack Path Simulation
	pathEngine := engine.NewAttackPathEngine(g.Graph)
	paths := pathEngine.FindPathsToCriticalAssets()

	if len(paths) > 0 {
		report += "\n\n"
		report += "==================================================\n"
		report += "⚔️  ATTACK PATH SIMULATION DETECTED VULNERABLE PATHS\n"
		report += "==================================================\n"
		for _, path := range paths {
			report += path.GenerateStory() + "\n"
		}
	} else {
		report += "\n\n[Attack Path Engine] No complete attack paths to critical assets found (yet).\n"
	}

	return report, nil
}
