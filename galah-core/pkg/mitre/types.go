package mitre

import (
	"time"
)

// AttackTechnique represents a MITRE ATT&CK technique
type AttackTechnique struct {
	ID          string            `json:"id"`          // e.g., "T1190"
	Name        string            `json:"name"`        // e.g., "Exploit Public-Facing Application"
	Tactic      string            `json:"tactic"`      // e.g., "Initial Access"
	Description string            `json:"description"`
	SubTechniques []SubTechnique   `json:"sub_techniques,omitempty"`
	DataSources []string          `json:"data_sources,omitempty"`
	Platforms   []string          `json:"platforms,omitempty"`
	Keywords    []string          `json:"keywords,omitempty"`     // For pattern matching
	Patterns    []PatternMatcher  `json:"patterns,omitempty"`     // HTTP-specific patterns
}

// SubTechnique represents a MITRE ATT&CK sub-technique
type SubTechnique struct {
	ID          string           `json:"id"`          // e.g., "T1190.001"
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Keywords    []string         `json:"keywords,omitempty"`
	Patterns    []PatternMatcher `json:"patterns,omitempty"`
}

// PatternMatcher defines patterns for detecting techniques in HTTP traffic
type PatternMatcher struct {
	Type        string   `json:"type"`        // "header", "url", "body", "method", "user_agent"
	Pattern     string   `json:"pattern"`     // Regex or literal string
	IsRegex     bool     `json:"is_regex"`
	CaseSensitive bool   `json:"case_sensitive"`
	Weight      float64  `json:"weight"`      // Pattern confidence weight (0.0-1.0)
}

// TechniqueMatch represents a detected MITRE technique with confidence
type TechniqueMatch struct {
	Technique   AttackTechnique   `json:"technique"`
	SubTechnique *SubTechnique    `json:"sub_technique,omitempty"`
	Confidence  float64          `json:"confidence"`      // 0.0-1.0
	Evidence    []Evidence       `json:"evidence"`        // What triggered the match
	Timestamp   time.Time        `json:"timestamp"`
}

// Evidence represents evidence for a technique detection
type Evidence struct {
	Type        string  `json:"type"`        // "pattern_match", "keyword_match", "behavioral"
	Source      string  `json:"source"`      // "url", "header", "body", etc.
	Value       string  `json:"value"`       // The actual matched content
	Pattern     string  `json:"pattern"`     // The pattern that matched
	Weight      float64 `json:"weight"`      // Evidence weight
}

// TacticMapping maps MITRE tactics to their techniques
type TacticMapping struct {
	Tactic      string            `json:"tactic"`
	Description string            `json:"description"`
	Techniques  []AttackTechnique `json:"techniques"`
}

// HTTPAttackMapping represents the mapping of HTTP-specific attacks to MITRE
type HTTPAttackMapping struct {
	AttackType     string            `json:"attack_type"`     // "sql_injection", "xss", etc.
	PrimaryTactic  string            `json:"primary_tactic"`  // Most common tactic for this attack
	Techniques     []string          `json:"techniques"`      // List of technique IDs
	Confidence     float64           `json:"confidence"`      // Base confidence for this mapping
	Prerequisites  []string          `json:"prerequisites,omitempty"`  // Required conditions
}

// ClassificationResult represents the result of MITRE classification
type ClassificationResult struct {
	Matches         []TechniqueMatch    `json:"matches"`
	PrimaryTactic   string              `json:"primary_tactic,omitempty"`
	OverallRisk     float64             `json:"overall_risk"`     // 0.0-10.0
	Confidence      float64             `json:"confidence"`       // 0.0-1.0
	AttackStage     string              `json:"attack_stage"`     // "reconnaissance", "initial_access", etc.
	Recommendations []string            `json:"recommendations,omitempty"`
}

// ThreatActor represents known threat actor patterns
type ThreatActor struct {
	Name            string   `json:"name"`
	Groups          []string `json:"groups,omitempty"`
	PreferredTactics []string `json:"preferred_tactics,omitempty"`
	CommonTechniques []string `json:"common_techniques,omitempty"`
	Indicators      []string `json:"indicators,omitempty"`  // Behavioral indicators
}

// AttackCampaign represents a series of related attacks
type AttackCampaign struct {
	ID              string           `json:"id"`
	SessionID       string           `json:"session_id"`
	StartTime       time.Time        `json:"start_time"`
	EndTime         time.Time        `json:"end_time,omitempty"`
	Techniques      []TechniqueMatch `json:"techniques"`
	Progression     []string         `json:"progression"`     // Technique progression over time
	ThreatActor     *ThreatActor     `json:"threat_actor,omitempty"`
	ObjectiveLikely string           `json:"objective_likely,omitempty"`
}