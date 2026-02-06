package tests

import (
	"os"
	"testing"

	"github.com/user/gosec-adk/pkg/engine"
)

func TestSnapshotOperations(t *testing.T) {
	// 1. Setup Baseline Graph
	baseline := engine.NewUnifiedGraph()
	findings := []engine.Finding{
		{
			SourceTool: "ToolA",
			Category:   "Test",
			Asset:      "Asset1",
			Evidence:   "Finding 1", // Will be UNCHANGED
			Severity:   5,
		},
		{
			SourceTool: "ToolA",
			Category:   "Test",
			Asset:      "Asset2",
			Evidence:   "Finding 2", // Will be FIXED (missing in new scan)
			Severity:   5,
		},
	}
	baseline.AddFindings(findings)

	// 2. Save Snapshot
	tmpFile := "test_snapshot.json"
	defer os.Remove(tmpFile)

	err := baseline.SaveSnapshot(tmpFile)
	if err != nil {
		t.Fatalf("Failed to save snapshot: %v", err)
	}

	// 3. Setup New Graph (Current Scan)
	current := engine.NewUnifiedGraph()
	newFindings := []engine.Finding{
		{
			SourceTool: "ToolA",
			Category:   "Test",
			Asset:      "Asset1",
			Evidence:   "Finding 1", // Same as baseline -> UNCHANGED
			Severity:   5,
		},
		{
			SourceTool: "ToolA",
			Category:   "Test",
			Asset:      "Asset3",
			Evidence:   "Finding 3", // New finding -> NEW RISK
			Severity:   8,
		},
	}
	current.AddFindings(newFindings)

	// 4. Load Baseline from File
	loadedBaseline := engine.NewUnifiedGraph()
	err = loadedBaseline.LoadSnapshot(tmpFile)
	if err != nil {
		t.Fatalf("Failed to load snapshot: %v", err)
	}

	// 5. Verify Loaded Content
	if len(loadedBaseline.Findings) != 2 {
		t.Errorf("Expected 2 findings in loaded baseline, got %d", len(loadedBaseline.Findings))
	}

	// 6. Compare Current vs Baseline
	diff := current.CompareSnapshot(loadedBaseline)

	// 7. Assertions
	
	// Unchanged: Finding 1
	if len(diff.Unchanged) != 1 {
		t.Errorf("Expected 1 unchanged finding, got %d", len(diff.Unchanged))
	} else if diff.Unchanged[0].Asset != "Asset1" {
		t.Errorf("Expected Unchanged to be Asset1, got %s", diff.Unchanged[0].Asset)
	}

	// New: Finding 3
	if len(diff.New) != 1 {
		t.Errorf("Expected 1 new finding, got %d", len(diff.New))
	} else if diff.New[0].Asset != "Asset3" {
		t.Errorf("Expected New to be Asset3, got %s", diff.New[0].Asset)
	}

	// Fixed: Finding 2 (in baseline, not in current)
	if len(diff.Fixed) != 1 {
		t.Errorf("Expected 1 fixed finding, got %d", len(diff.Fixed))
	} else if diff.Fixed[0].Asset != "Asset2" {
		t.Errorf("Expected Fixed to be Asset2, got %s", diff.Fixed[0].Asset)
	}
}
