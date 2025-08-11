package response

import "time"

// EventAnalysis represents analysis of a security event (simplified version for response generation)
type EventAnalysis struct {
	AttackType       string            `json:"attackType,omitempty"`
	Confidence       float64           `json:"confidence"`
	MITRETechniques  []string          `json:"mitreTechniques,omitempty"`
	PayloadAnalysis  PayloadInfo       `json:"payloadAnalysis,omitempty"`
	Anomalies        []string          `json:"anomalies,omitempty"`
	RiskScore        float64           `json:"riskScore"`
	Timestamp        time.Time         `json:"timestamp"`
	SessionID        string            `json:"sessionId,omitempty"`
	RequestID        string            `json:"requestId,omitempty"`
}

// PayloadInfo contains information about payload analysis
type PayloadInfo struct {
	Length     int     `json:"length"`
	Entropy    float64 `json:"entropy"`
	Complexity float64 `json:"complexity"`
	Encoding   string  `json:"encoding,omitempty"`
	Type       string  `json:"type,omitempty"`
	Patterns   []string `json:"patterns,omitempty"`
}

// AttackTimeline represents the timeline of attack activities
type AttackTimeline struct {
	SessionID    string                 `json:"sessionId"`
	StartTime    time.Time              `json:"startTime"`
	EndTime      time.Time              `json:"endTime"`
	Duration     time.Duration          `json:"duration"`
	EventCount   int                    `json:"eventCount"`
	Events       []EventAnalysis        `json:"events"`
	Progression  []string               `json:"progression"`
	Patterns     []AttackPattern        `json:"patterns"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// AttackPattern represents an identified attack pattern in the timeline
type AttackPattern struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Confidence  float64   `json:"confidence"`
	StartTime   time.Time `json:"startTime"`
	EndTime     time.Time `json:"endTime"`
	Events      []string  `json:"events"`
}

// AttackerProfile represents the profile of an attacker based on behavioral analysis
type AttackerProfile struct {
	SessionID          string                 `json:"sessionId"`
	AttackerType       string                 `json:"attackerType"`
	SkillLevel         string                 `json:"skillLevel"`
	ToolsUsed          []string               `json:"toolsUsed"`
	TechniquesUsed     []string               `json:"techniquesUsed"`
	BehaviorMetrics    BehaviorMetrics        `json:"behaviorMetrics"`
	ThreatLevel        string                 `json:"threatLevel"`
	Confidence         float64                `json:"confidence"`
	FirstSeen          time.Time              `json:"firstSeen"`
	LastSeen           time.Time              `json:"lastSeen"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
}

// BehaviorMetrics contains quantified behavioral characteristics
type BehaviorMetrics struct {
	RequestRate          float64 `json:"requestRate"`
	AttackDiversity      float64 `json:"attackDiversity"`
	TimingConsistency    float64 `json:"timingConsistency"`
	ErrorRate            float64 `json:"errorRate"`
	PersistenceIndicator float64 `json:"persistenceIndicator"`
	SophisticationScore  float64 `json:"sophisticationScore"`
}