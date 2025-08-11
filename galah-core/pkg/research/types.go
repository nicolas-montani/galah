package research

import (
	"time"
)

// ResearchMetrics contains research-focused analytics data
type ResearchMetrics struct {
	SessionDuration     time.Duration     `json:"sessionDurationMs"`
	RequestCount        int               `json:"requestCount"`
	AttackComplexity    string            `json:"attackComplexity"`
	TechnicalSkillLevel string            `json:"technicalSkillLevel"`
	PersistenceScore    float64           `json:"persistenceScore"`
	EngagementScore     float64           `json:"engagementScore"`
	AttackProgression   []string          `json:"attackProgression,omitempty"`
	ToolsDetected       []string          `json:"toolsDetected,omitempty"`
	GeographicData      GeographicInfo    `json:"geographicData,omitempty"`
}

// GeographicInfo contains enriched geographic information
type GeographicInfo struct {
	Country     string  `json:"country,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	ASN         string  `json:"asn,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	IsVPN       bool    `json:"isVPN"`
	IsTor       bool    `json:"isTor"`
	IsHosting   bool    `json:"isHosting"`
}

// AttackTimeline represents the temporal progression of an attack
type AttackTimeline struct {
	SessionID    string                `json:"sessionID"`
	StartTime    time.Time             `json:"startTime"`
	EndTime      time.Time             `json:"endTime,omitempty"`
	Events       []AttackEvent         `json:"events"`
	Summary      AttackSummary         `json:"summary"`
}

// AttackEvent represents a single event in an attack timeline
type AttackEvent struct {
	Timestamp    time.Time             `json:"timestamp"`
	EventType    string                `json:"eventType"`
	Request      HTTPRequest           `json:"request"`
	Response     map[string]interface{} `json:"response,omitempty"`
	Analysis     EventAnalysis         `json:"analysis"`
}

// HTTPRequest contains information about the HTTP request with research extensions
type HTTPRequest struct {
	Body                string            `json:"body"`
	BodySha256          string            `json:"bodySha256"`
	Headers             map[string]string `json:"headers"`
	HeadersSorted       string            `json:"headersSorted"`
	HeadersSortedSha256 string            `json:"headersSortedSha256"`
	Method              string            `json:"method"`
	ProtocolVersion     string            `json:"protocolVersion"`
	Request             string            `json:"request"`
	SessionID           string            `json:"sessionID"`
	UserAgent           string            `json:"userAgent"`
	// Research-focused fields
	RequestSize         int64             `json:"requestSize"`
	ContentType         string            `json:"contentType"`
	RequestFingerprint  string            `json:"requestFingerprint"`
	AttackVectors       []string          `json:"attackVectors,omitempty"`
	SuspiciousPatterns  []string          `json:"suspiciousPatterns,omitempty"`
}

// EventAnalysis contains analysis results for a specific event
type EventAnalysis struct {
	AttackType       string            `json:"attackType,omitempty"`
	Confidence       float64           `json:"confidence"`
	MITRETechniques  []string          `json:"mitreTechniques,omitempty"`
	PayloadAnalysis  PayloadInfo       `json:"payloadAnalysis,omitempty"`
	Anomalies        []string          `json:"anomalies,omitempty"`
	RiskScore        float64           `json:"riskScore"`
}

// PayloadInfo contains analysis of request payloads
type PayloadInfo struct {
	Type            string            `json:"type"`
	EncodingSchemes []string          `json:"encodingSchemes,omitempty"`
	ObfuscationUsed bool              `json:"obfuscationUsed"`
	MaliciousKeywords []string        `json:"maliciousKeywords,omitempty"`
	Size            int64             `json:"size"`
	Entropy         float64           `json:"entropy,omitempty"`
}

// AttackSummary provides a summary of the entire attack session
type AttackSummary struct {
	TotalRequests       int               `json:"totalRequests"`
	UniqueAttackTypes   []string          `json:"uniqueAttackTypes"`
	HighestRiskScore    float64           `json:"highestRiskScore"`
	MostCommonTechnique string            `json:"mostCommonTechnique,omitempty"`
	AttackerProfile     AttackerProfile   `json:"attackerProfile"`
}

// AttackerProfile contains behavioral analysis of the attacker
type AttackerProfile struct {
	SkillLevel          string            `json:"skillLevel"`
	Automation          string            `json:"automation"`
	Persistence         string            `json:"persistence"`
	TargetFocus         []string          `json:"targetFocus,omitempty"`
	TacticalApproach    string            `json:"tacticalApproach,omitempty"`
	PreferredTools      []string          `json:"preferredTools,omitempty"`
	BehavioralPatterns  []string          `json:"behavioralPatterns,omitempty"`
}