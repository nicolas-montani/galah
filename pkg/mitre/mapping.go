package mitre

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/0x4d31/galah/pkg/research"
)

// Mapper provides MITRE ATT&CK mapping functionality for HTTP requests
type Mapper struct {
	classifier *Classifier
	campaigns  map[string]*AttackCampaign
	mutex      sync.RWMutex
}

// NewMapper creates a new MITRE ATT&CK mapper
func NewMapper(dataFile string) (*Mapper, error) {
	classifier, err := NewClassifier(dataFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create classifier: %w", err)
	}
	
	return &Mapper{
		classifier: classifier,
		campaigns:  make(map[string]*AttackCampaign),
	}, nil
}

// MapRequest maps an HTTP request to MITRE ATT&CK techniques
func (m *Mapper) MapRequest(r *http.Request, body string, sessionID string, attackVectors []string) *ClassificationResult {
	// Classify the request
	result := m.classifier.ClassifyRequest(r, body, attackVectors)
	
	// Update attack campaign tracking
	m.updateCampaign(sessionID, result.Matches)
	
	// Enhance result with campaign context
	m.enhanceWithCampaignContext(result, sessionID)
	
	return result
}

// updateCampaign updates the attack campaign for a session
func (m *Mapper) updateCampaign(sessionID string, matches []TechniqueMatch) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	campaign, exists := m.campaigns[sessionID]
	if !exists {
		campaign = &AttackCampaign{
			ID:         fmt.Sprintf("campaign_%s_%d", sessionID, time.Now().Unix()),
			SessionID:  sessionID,
			StartTime:  time.Now(),
			Techniques: []TechniqueMatch{},
			Progression: []string{},
		}
		m.campaigns[sessionID] = campaign
	}
	
	// Update campaign with new techniques
	campaign.EndTime = time.Now()
	for _, match := range matches {
		// Check if we already have this technique
		found := false
		for i, existing := range campaign.Techniques {
			if existing.Technique.ID == match.Technique.ID {
				// Update with better confidence if found
				if match.Confidence > existing.Confidence {
					campaign.Techniques[i] = match
				}
				found = true
				break
			}
		}
		
		if !found {
			campaign.Techniques = append(campaign.Techniques, match)
			campaign.Progression = append(campaign.Progression, match.Technique.ID)
		}
	}
	
	// Analyze threat actor patterns
	campaign.ThreatActor = m.analyzeThreatActor(campaign)
	
	// Determine likely objective
	campaign.ObjectiveLikely = m.determineObjective(campaign)
}

// enhanceWithCampaignContext enhances classification result with campaign context
func (m *Mapper) enhanceWithCampaignContext(result *ClassificationResult, sessionID string) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	campaign, exists := m.campaigns[sessionID]
	if !exists {
		return
	}
	
	// Add campaign progression context
	if len(campaign.Progression) > 1 {
		result.Recommendations = append(result.Recommendations, 
			"Multi-stage attack detected - implement advanced threat detection")
	}
	
	// Enhance risk based on campaign progression
	if len(campaign.Techniques) > 3 {
		result.OverallRisk += 1.0 // Persistent attacker
	}
	
	// Add threat actor context if identified
	if campaign.ThreatActor != nil {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("Consider threat actor patterns: %s", campaign.ThreatActor.Name))
	}
}

// analyzeThreatActor attempts to identify threat actor patterns
func (m *Mapper) analyzeThreatActor(campaign *AttackCampaign) *ThreatActor {
	if len(campaign.Techniques) < 2 {
		return nil
	}
	
	// Extract techniques and tactics
	techniques := make(map[string]bool)
	tactics := make(map[string]bool)
	
	for _, match := range campaign.Techniques {
		techniques[match.Technique.ID] = true
		tactics[match.Technique.Tactic] = true
	}
	
	// Pattern matching for known threat actor behaviors
	if techniques["T1190"] && techniques["T1505"] {
		return &ThreatActor{
			Name:             "Web Application Specialist",
			PreferredTactics: []string{"Initial Access", "Persistence"},
			CommonTechniques: []string{"T1190", "T1505"},
			Indicators:       []string{"web_exploitation", "webshell_deployment"},
		}
	}
	
	if tactics["Reconnaissance"] && tactics["Discovery"] {
		return &ThreatActor{
			Name:             "Reconnaissance Specialist", 
			PreferredTactics: []string{"Reconnaissance", "Discovery"},
			CommonTechniques: extractTechniqueIDs(campaign.Techniques),
			Indicators:       []string{"systematic_scanning", "information_gathering"},
		}
	}
	
	if len(tactics) >= 4 {
		return &ThreatActor{
			Name:             "Advanced Persistent Threat",
			PreferredTactics: extractTactics(campaign.Techniques),
			CommonTechniques: extractTechniqueIDs(campaign.Techniques),
			Indicators:       []string{"multi_stage_attack", "persistent_presence"},
		}
	}
	
	return nil
}

// determineObjective determines the likely objective of the attack campaign
func (m *Mapper) determineObjective(campaign *AttackCampaign) string {
	tactics := make(map[string]bool)
	techniques := make(map[string]bool)
	
	for _, match := range campaign.Techniques {
		tactics[match.Technique.Tactic] = true
		techniques[match.Technique.ID] = true
	}
	
	// Data extraction objective
	if techniques["T1083"] || tactics["Discovery"] {
		return "information_gathering"
	}
	
	// System compromise objective
	if techniques["T1190"] && techniques["T1505"] {
		return "system_compromise"
	}
	
	// Reconnaissance objective
	if tactics["Reconnaissance"] && !tactics["Initial Access"] {
		return "reconnaissance"
	}
	
	// Multi-stage attack
	if len(tactics) >= 3 {
		return "advanced_persistent_threat"
	}
	
	return "unknown"
}

// ConvertToResearchEvent converts MITRE classification to research event analysis
func (m *Mapper) ConvertToResearchEvent(result *ClassificationResult) *research.EventAnalysis {
	if result == nil {
		return &research.EventAnalysis{}
	}
	
	// Extract primary attack type and MITRE techniques
	attackType := "unknown"
	mitreTechniques := []string{}
	
	for _, match := range result.Matches {
		mitreTechniques = append(mitreTechniques, match.Technique.ID)
		if match.SubTechnique != nil {
			mitreTechniques = append(mitreTechniques, match.SubTechnique.ID)
		}
	}
	
	// Determine attack type from primary tactic
	if result.PrimaryTactic != "" {
		attackType = strings.ToLower(strings.ReplaceAll(result.PrimaryTactic, " ", "_"))
	}
	
	return &research.EventAnalysis{
		AttackType:      attackType,
		Confidence:      result.Confidence,
		MITRETechniques: mitreTechniques,
		RiskScore:       result.OverallRisk,
		Anomalies:       []string{}, // Will be filled by other analysis
		PayloadAnalysis: research.PayloadInfo{}, // Will be filled by other analysis
	}
}

// GetCampaign returns attack campaign information for a session
func (m *Mapper) GetCampaign(sessionID string) (*AttackCampaign, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	campaign, exists := m.campaigns[sessionID]
	return campaign, exists
}

// GetAllCampaigns returns all active attack campaigns
func (m *Mapper) GetAllCampaigns() map[string]*AttackCampaign {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Return a copy to avoid concurrent access issues
	campaigns := make(map[string]*AttackCampaign)
	for id, campaign := range m.campaigns {
		campaigns[id] = campaign
	}
	
	return campaigns
}

// CleanupOldCampaigns removes old campaigns to prevent memory leaks
func (m *Mapper) CleanupOldCampaigns(maxAge time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	cutoff := time.Now().Add(-maxAge)
	for sessionID, campaign := range m.campaigns {
		if campaign.EndTime.Before(cutoff) {
			delete(m.campaigns, sessionID)
		}
	}
}

// GenerateReport generates a comprehensive MITRE ATT&CK report for a session
func (m *Mapper) GenerateReport(sessionID string) *MITREReport {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	campaign, exists := m.campaigns[sessionID]
	if !exists {
		return &MITREReport{
			SessionID: sessionID,
			Summary:   "No MITRE ATT&CK techniques detected",
		}
	}
	
	report := &MITREReport{
		SessionID:         sessionID,
		StartTime:         campaign.StartTime,
		EndTime:           campaign.EndTime,
		TotalTechniques:   len(campaign.Techniques),
		TechniqueMatches:  campaign.Techniques,
		TacticProgression: m.extractTacticProgression(campaign),
		ThreatActor:       campaign.ThreatActor,
		Objective:         campaign.ObjectiveLikely,
		RiskAssessment:    m.assessCampaignRisk(campaign),
		Recommendations:   m.generateCampaignRecommendations(campaign),
	}
	
	report.Summary = m.generateSummary(report)
	
	return report
}

// MITREReport represents a comprehensive MITRE ATT&CK analysis report
type MITREReport struct {
	SessionID         string           `json:"session_id"`
	StartTime         time.Time        `json:"start_time"`
	EndTime           time.Time        `json:"end_time"`
	TotalTechniques   int              `json:"total_techniques"`
	TechniqueMatches  []TechniqueMatch `json:"technique_matches"`
	TacticProgression []string         `json:"tactic_progression"`
	ThreatActor       *ThreatActor     `json:"threat_actor,omitempty"`
	Objective         string           `json:"objective"`
	RiskAssessment    RiskAssessment   `json:"risk_assessment"`
	Recommendations   []string         `json:"recommendations"`
	Summary           string           `json:"summary"`
}

// RiskAssessment represents risk assessment for a campaign
type RiskAssessment struct {
	OverallRisk   float64 `json:"overall_risk"`   // 0-10 scale
	Sophistication string  `json:"sophistication"` // "low", "medium", "high"
	Persistence   string  `json:"persistence"`    // "low", "medium", "high"
	Impact        string  `json:"impact"`         // "low", "medium", "high"
}

// Helper functions

func extractTechniqueIDs(matches []TechniqueMatch) []string {
	var ids []string
	for _, match := range matches {
		ids = append(ids, match.Technique.ID)
	}
	return ids
}

func extractTactics(matches []TechniqueMatch) []string {
	tacticsMap := make(map[string]bool)
	for _, match := range matches {
		tacticsMap[match.Technique.Tactic] = true
	}
	
	var tactics []string
	for tactic := range tacticsMap {
		tactics = append(tactics, tactic)
	}
	return tactics
}

func (m *Mapper) extractTacticProgression(campaign *AttackCampaign) []string {
	tacticsMap := make(map[string]time.Time)
	
	for _, match := range campaign.Techniques {
		tactic := match.Technique.Tactic
		if existing, exists := tacticsMap[tactic]; !exists || match.Timestamp.After(existing) {
			tacticsMap[tactic] = match.Timestamp
		}
	}
	
	// Sort tactics by timestamp
	type tacticTime struct {
		tactic string
		time   time.Time
	}
	
	var tacticTimes []tacticTime
	for tactic, timestamp := range tacticsMap {
		tacticTimes = append(tacticTimes, tacticTime{tactic, timestamp})
	}
	
	// Simple sort by time
	for i := 0; i < len(tacticTimes)-1; i++ {
		for j := i + 1; j < len(tacticTimes); j++ {
			if tacticTimes[i].time.After(tacticTimes[j].time) {
				tacticTimes[i], tacticTimes[j] = tacticTimes[j], tacticTimes[i]
			}
		}
	}
	
	var progression []string
	for _, tt := range tacticTimes {
		progression = append(progression, tt.tactic)
	}
	
	return progression
}

func (m *Mapper) assessCampaignRisk(campaign *AttackCampaign) RiskAssessment {
	// Calculate overall risk
	maxRisk := 0.0
	for _, match := range campaign.Techniques {
		risk := m.classifier.getTacticRiskScore(match.Technique.Tactic) * match.Confidence
		if risk > maxRisk {
			maxRisk = risk
		}
	}
	
	// Assess sophistication
	sophistication := "low"
	if len(campaign.Techniques) > 5 {
		sophistication = "high"
	} else if len(campaign.Techniques) > 2 {
		sophistication = "medium"
	}
	
	// Assess persistence
	duration := campaign.EndTime.Sub(campaign.StartTime)
	persistence := "low"
	if duration.Hours() > 24 {
		persistence = "high"
	} else if duration.Hours() > 1 {
		persistence = "medium"
	}
	
	// Assess impact
	impact := "low"
	tactics := extractTactics(campaign.Techniques)
	if len(tactics) > 4 {
		impact = "high"
	} else if len(tactics) > 2 {
		impact = "medium"
	}
	
	return RiskAssessment{
		OverallRisk:    maxRisk,
		Sophistication: sophistication,
		Persistence:    persistence,
		Impact:         impact,
	}
}

func (m *Mapper) generateCampaignRecommendations(campaign *AttackCampaign) []string {
	recommendations := []string{}
	
	tactics := make(map[string]bool)
	for _, match := range campaign.Techniques {
		tactics[match.Technique.Tactic] = true
	}
	
	if tactics["Initial Access"] {
		recommendations = append(recommendations, "Strengthen perimeter defenses and input validation")
	}
	
	if tactics["Persistence"] {
		recommendations = append(recommendations, "Monitor for persistence mechanisms and unauthorized changes")
	}
	
	if tactics["Discovery"] {
		recommendations = append(recommendations, "Implement network segmentation and access controls")
	}
	
	if len(campaign.Techniques) > 5 {
		recommendations = append(recommendations, "Deploy advanced threat detection and response capabilities")
	}
	
	return recommendations
}

func (m *Mapper) generateSummary(report *MITREReport) string {
	if report.TotalTechniques == 0 {
		return "No MITRE ATT&CK techniques detected in this session"
	}
	
	summary := fmt.Sprintf("Detected %d MITRE ATT&CK techniques across %d tactics. ",
		report.TotalTechniques, len(report.TacticProgression))
	
	if report.ThreatActor != nil {
		summary += fmt.Sprintf("Identified threat actor pattern: %s. ", report.ThreatActor.Name)
	}
	
	summary += fmt.Sprintf("Campaign objective likely: %s. ", report.Objective)
	summary += fmt.Sprintf("Risk level: %.1f/10.", report.RiskAssessment.OverallRisk)
	
	return summary
}