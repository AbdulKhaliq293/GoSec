package engine

// Finding represents a normalized security finding from any tool
type Finding struct {
	ID              string   `json:"id"`
	SourceTool      string   `json:"source_tool"`
	Category        string   `json:"category"` // network / auth / crypto / kernel / container / filesystem
	Severity        int      `json:"severity"` // normalized 1-10
	Confidence      string   `json:"confidence"`
	Asset           string   `json:"asset"` // ip / hostname / container / port / file
	Evidence        string   `json:"evidence"`
	RemediationHint string   `json:"remediation_hint"`
	ComplianceList  []string `json:"compliance_mapping"` // CIS, ISO27001, NIST, etc
}
