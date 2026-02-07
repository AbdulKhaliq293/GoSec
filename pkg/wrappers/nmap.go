package wrappers

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/user/gosec-adk/pkg/engine"
)

// NmapWrapper implements the Tool interface for Nmap
type NmapWrapper struct{
	Graph *engine.UnifiedGraph
}

func (n *NmapWrapper) Name() string {
	return "RunNmapScan"
}

func (n *NmapWrapper) Description() string {
	return "Runs an Nmap scan on a target host to find open ports and services."
}

func (n *NmapWrapper) Schema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"target": map[string]interface{}{
				"type":        "string",
				"description": "IP address or hostname to scan",
			},
			"ports": map[string]interface{}{
				"type":        "string",
				"description": "Ports to scan (e.g., '80,443' or '1-1000'). Defaults to Fast Scan (-F) if not provided.",
			},
		},
		"required": []string{"target"},
	}
}

func (n *NmapWrapper) Execute(ctx context.Context, args map[string]interface{}, progress func(string)) (string, error) {
	var target string
	var ports string

	// Handle structured args (if provided correctly)
	if t, ok := args["target"].(string); ok {
		target = t
	}
	if p, ok := args["ports"].(string); ok {
		ports = p
	}

	// Handle simplified 'args' string from Gemini MVP
	if val, ok := args["args"].(string); ok && target == "" {
		parts := strings.Fields(val)
		for _, p := range parts {
			if !strings.HasPrefix(p, "-") {
				target = p
			}
		}
		if target == "" {
			target = val
		}
	}

	if target == "" {
		return "Error: target argument is required. Please specify a hostname or IP.", nil
	}

	// Use temporary file for XML output
	xmlFile, err := os.CreateTemp("", "nmap-*.xml")
	if err != nil {
		return fmt.Sprintf("Error creating temp file: %v", err), nil
	}
	xmlPath := xmlFile.Name()
	xmlFile.Close()
	defer os.Remove(xmlPath)

	cmdArgs := []string{"-F", target, "-oX", xmlPath} // Default to fast scan + XML output
	if ports != "" {
		cmdArgs = []string{"-p", ports, target, "-oX", xmlPath}
	}

	fmt.Printf("[Nmap] Scanning %s... Output will stream below:\n", target)
	cmd := exec.CommandContext(ctx, "nmap", cmdArgs...)

	var buf bytes.Buffer
	mw := io.MultiWriter(os.Stdout, &buf)

	cmd.Stdout = mw
	cmd.Stderr = mw

	err = cmd.Run()
	if err != nil {
		return fmt.Sprintf("Nmap failed: %v. Output:\n%s", err, buf.String()), nil
	}

	// Parse XML and populate graph
	if n.Graph != nil {
		if err := ingestNmapXML(xmlPath, n.Graph); err != nil {
			fmt.Printf("Warning: Failed to ingest Nmap XML to Graph: %v\n", err)
		} else {
			fmt.Printf("[UnifiedGraph] Successfully ingested Nmap scan data (Nodes, Edges, Findings).\n")
		}
	}

	return buf.String(), nil
}

// XML Structures for parsing
type NmapRun struct {
	Hosts []NmapHost `xml:"host"`
}
type NmapHost struct {
	Addresses []NmapAddress `xml:"address"`
	Ports     NmapPorts     `xml:"ports"`
}
type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}
type NmapPorts struct {
	Ports []NmapPort `xml:"port"`
}
type NmapPort struct {
	PortID   string      `xml:"portid,attr"`
	Protocol string      `xml:"protocol,attr"`
	State    NmapState   `xml:"state"`
	Service  NmapService `xml:"service"`
}
type NmapState struct {
	State string `xml:"state,attr"`
}
type NmapService struct {
	Name string `xml:"name,attr"`
}

func ingestNmapXML(path string, g *engine.UnifiedGraph) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var run NmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return err
	}

	// Ensure "Attacker" node exists (The Scanner)
	attackerNode := engine.Node{
		ID:    "attacker",
		Type:  "attacker",
		Label: "External Attacker / Scanner",
	}
	g.AddNode(attackerNode)

	var newFindings []engine.Finding

	for _, host := range run.Hosts {
		var ip string
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				ip = addr.Addr
				break
			}
		}
		if ip == "" && len(host.Addresses) > 0 {
			ip = host.Addresses[0].Addr
		}
		if ip == "" {
			continue
		}

		// Create Host Node
		hostNode := engine.Node{
			ID:    ip,
			Type:  "host",
			Label: ip,
		}
		g.AddNode(hostNode)

		// Edge: Attacker -> Host (Network Reachable)
		g.AddEdge(engine.Edge{
			SourceID: "attacker",
			TargetID: ip,
			Type:     "network_reachability",
			Weight:   1,
		})

		for _, port := range host.Ports.Ports {
			if port.State.State == "open" {
				// Create Service Node
				serviceID := fmt.Sprintf("%s:%s", ip, port.PortID)
				serviceNode := engine.Node{
					ID:    serviceID,
					Type:  "service",
					Label: fmt.Sprintf("%s/%s %s", port.PortID, port.Protocol, port.Service.Name),
					Metadata: map[string]string{
						"port":     port.PortID,
						"protocol": port.Protocol,
						"service":  port.Service.Name,
					},
				}
				g.AddNode(serviceNode)

				// Edge: Host -> Service (Exposes)
				g.AddEdge(engine.Edge{
					SourceID: ip,
					TargetID: serviceID,
					Type:     "exposes",
					Weight:   1,
				})

				// Create Finding
				severity := 5 // Default medium
				if port.PortID == "22" || port.PortID == "3389" || port.PortID == "23" {
					severity = 8
				}

				f := engine.Finding{
					ID:              fmt.Sprintf("nmap-%s-%s-%s", ip, port.PortID, port.Protocol),
					SourceTool:      "Nmap",
					Category:        "network",
					Severity:        severity,
					Confidence:      "High",
					Asset:           ip, // Link to Host Node
					Evidence:        fmt.Sprintf("Port %s/%s is open (Service: %s)", port.PortID, port.Protocol, port.Service.Name),
					RemediationHint: fmt.Sprintf("Verify if port %s needs to be exposed. Use firewall rules to restrict access.", port.PortID),
				}
				newFindings = append(newFindings, f)
			}
		}
	}
	
	g.AddFindings(newFindings)
	return nil
}
