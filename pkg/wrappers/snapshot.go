package wrappers

import (
	"context"
	"fmt"
	"strings"

	"github.com/user/gosec-adk/pkg/engine"
)

const DefaultSnapshotPath = ".gosec-snapshot.json"

// SaveSnapshotWrapper implements the Tool interface for saving the current graph state
type SaveSnapshotWrapper struct {
	Graph *engine.UnifiedGraph
}

func (s *SaveSnapshotWrapper) Name() string {
	return "SaveSnapshot"
}

func (s *SaveSnapshotWrapper) Description() string {
	return "Saves the current security findings to a snapshot file for future comparison."
}

func (s *SaveSnapshotWrapper) Schema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"filename": map[string]interface{}{
				"type":        "string",
				"description": "Optional filename for the snapshot (default: .gosec-snapshot.json)",
			},
		},
	}
}

func (s *SaveSnapshotWrapper) Execute(ctx context.Context, args map[string]interface{}, progress func(string)) (string, error) {
	if s.Graph == nil {
		return "Error: Unified Graph not initialized.", nil
	}

	filename := DefaultSnapshotPath
	if val, ok := args["filename"].(string); ok && val != "" {
		filename = val
	}

	err := s.Graph.SaveSnapshot(filename)
	if err != nil {
		return fmt.Sprintf("Error saving snapshot: %v", err), nil
	}

	return fmt.Sprintf("Successfully saved %d findings to snapshot '%s'.", len(s.Graph.Findings), filename), nil
}

// DiffSnapshotWrapper implements the Tool interface for comparing current findings with a baseline
type DiffSnapshotWrapper struct {
	Graph *engine.UnifiedGraph
}

func (d *DiffSnapshotWrapper) Name() string {
	return "CompareWithBaseline"
}

func (d *DiffSnapshotWrapper) Description() string {
	return "Compares the current security findings against a previously saved snapshot to identify New, Fixed, and Unchanged risks."
}

func (d *DiffSnapshotWrapper) Schema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"filename": map[string]interface{}{
				"type":        "string",
				"description": "Optional filename of the baseline snapshot to compare against (default: .gosec-snapshot.json)",
			},
		},
	}
}

func (d *DiffSnapshotWrapper) Execute(ctx context.Context, args map[string]interface{}, progress func(string)) (string, error) {
	if d.Graph == nil {
		return "Error: Unified Graph not initialized.", nil
	}

	filename := DefaultSnapshotPath
	if val, ok := args["filename"].(string); ok && val != "" {
		filename = val
	}

	baseline := engine.NewUnifiedGraph()
	if err := baseline.LoadSnapshot(filename); err != nil {
		return fmt.Sprintf("Error loading baseline snapshot '%s': %v. Have you run a scan and saved a snapshot before?", filename, err), nil
	}

	diff := d.Graph.CompareSnapshot(baseline)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Snapshot Comparison (vs %s):\n", filename))
	sb.WriteString("--------------------------------------------------\n")

	// NEW RISKS
	sb.WriteString(fmt.Sprintf("NEW RISKS: %d\n", len(diff.New)))
	for _, f := range diff.New {
		sb.WriteString(fmt.Sprintf("  [+] [%d/10] %s (%s) - %s\n", f.Severity, f.Category, f.SourceTool, f.Evidence))
	}
	sb.WriteString("\n")

	// FIXED RISKS
	sb.WriteString(fmt.Sprintf("FIXED RISKS: %d\n", len(diff.Fixed)))
	for _, f := range diff.Fixed {
		sb.WriteString(fmt.Sprintf("  [-] [%d/10] %s (%s) - %s\n", f.Severity, f.Category, f.SourceTool, f.Evidence))
	}
	sb.WriteString("\n")

	// UNCHANGED RISKS
	sb.WriteString(fmt.Sprintf("UNCHANGED RISKS: %d\n", len(diff.Unchanged)))
	// We might not list all unchanged to save tokens, or maybe summary only?
	// The prompt said "Then show: NEW... FIXED... UNCHANGED...".
	// Engineers love detail, but context window is finite. Let's show counts and maybe top 5?
	// For now, let's list them but keep it brief.
	if len(diff.Unchanged) > 0 {
		sb.WriteString("  (Listing top 10 unchanged)\n")
		count := 0
		for _, f := range diff.Unchanged {
			sb.WriteString(fmt.Sprintf("  [=] [%d/10] %s (%s) - %s\n", f.Severity, f.Category, f.SourceTool, f.Evidence))
			count++
			if count >= 10 {
				sb.WriteString(fmt.Sprintf("  ... and %d more.\n", len(diff.Unchanged)-10))
				break
			}
		}
	}

	return sb.String(), nil
}
