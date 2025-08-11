package analytics

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0x4d31/galah/pkg/mitre"
	"github.com/0x4d31/galah/pkg/research"
)

// ResearchAnalyzer provides advanced analytics for research purposes
type ResearchAnalyzer struct {
	sessions    map[string]*SessionTracker
	sessionsMux sync.RWMutex
	Metrics     *MetricsCalculator
	MitreMapper *mitre.Mapper
	dataDir     string
}

// SessionTracker tracks attack session progression
type SessionTracker struct {
	SessionID       string
	StartTime       time.Time
	LastActivity    time.Time
	RequestCount    int
	AttackVectors   map[string]int
	RiskScores      []float64
	UserAgents      map[string]int
	SourceIPs       map[string]int
	AttackTimeline  []research.AttackEvent
	BehaviorProfile research.AttackerProfile
	mutex           sync.RWMutex
}

// NewResearchAnalyzer creates a new research analyzer
func NewResearchAnalyzer(dataDir string) *ResearchAnalyzer {
	if dataDir == "" {
		dataDir = "research_data"
	}
	
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Printf("Failed to create research data directory: %v", err)
	}
	
	// Initialize MITRE mapper
	mitreMapper, err := mitre.NewMapper("data/mitre/techniques.json")
	if err != nil {
		log.Printf("Failed to initialize MITRE mapper: %v", err)
		mitreMapper = nil
	}
	
	return &ResearchAnalyzer{
		sessions:    make(map[string]*SessionTracker),
		Metrics:     NewMetricsCalculator(),
		MitreMapper: mitreMapper,
		dataDir:     dataDir,
	}
}

// AnalyzeRequest performs comprehensive analysis of an HTTP request
func (ra *ResearchAnalyzer) AnalyzeRequest(r *http.Request, body string, sessionID string, sourceIP string) *research.EventAnalysis {
	// Calculate metrics
	attackVectors := ra.Metrics.DetectAttackVectors(r, body)
	suspiciousPatterns := ra.Metrics.DetectSuspiciousPatterns(r, body)
	entropy := ra.Metrics.CalculatePayloadEntropy(body)
	riskScore := ra.Metrics.CalculateRiskScore(attackVectors, suspiciousPatterns, entropy)
	
	// Update session tracking
	ra.UpdateSession(sessionID, sourceIP, r, attackVectors, riskScore)
	
	// Determine attack type
	attackType := ra.determineAttackType(attackVectors, suspiciousPatterns)
	
	// Calculate confidence based on number of indicators
	confidence := ra.calculateConfidence(attackVectors, suspiciousPatterns, entropy)
	
	// Detect anomalies
	anomalies := ra.detectAnomalies(r, body, entropy)
	
	// Analyze payload
	payloadInfo := ra.analyzePayload(body, attackVectors)
	
	// MITRE ATT&CK classification
	var mitreTechniques []string
	if ra.MitreMapper != nil {
		mitreResult := ra.MitreMapper.MapRequest(r, body, sessionID, attackVectors)
		for _, match := range mitreResult.Matches {
			mitreTechniques = append(mitreTechniques, match.Technique.ID)
			if match.SubTechnique != nil {
				mitreTechniques = append(mitreTechniques, match.SubTechnique.ID)
			}
		}
		
		// Update risk score with MITRE assessment
		if mitreResult.OverallRisk > riskScore {
			riskScore = mitreResult.OverallRisk
		}
		
		// Update attack type with MITRE primary tactic if more specific
		if mitreResult.PrimaryTactic != "" && attackType == "unknown" {
			attackType = strings.ToLower(strings.ReplaceAll(mitreResult.PrimaryTactic, " ", "_"))
		}
	}
	
	return &research.EventAnalysis{
		AttackType:      attackType,
		Confidence:      confidence,
		MITRETechniques: mitreTechniques,
		PayloadAnalysis: payloadInfo,
		Anomalies:       anomalies,
		RiskScore:       riskScore,
	}
}

// UpdateSession updates session tracking information
func (ra *ResearchAnalyzer) UpdateSession(sessionID, sourceIP string, r *http.Request, attackVectors []string, riskScore float64) {
	ra.sessionsMux.Lock()
	defer ra.sessionsMux.Unlock()
	
	session, exists := ra.sessions[sessionID]
	if !exists {
		session = &SessionTracker{
			SessionID:       sessionID,
			StartTime:       time.Now(),
			AttackVectors:   make(map[string]int),
			UserAgents:      make(map[string]int),
			SourceIPs:       make(map[string]int),
			AttackTimeline:  []research.AttackEvent{},
		}
		ra.sessions[sessionID] = session
	}
	
	session.mutex.Lock()
	defer session.mutex.Unlock()
	
	session.LastActivity = time.Now()
	session.RequestCount++
	session.RiskScores = append(session.RiskScores, riskScore)
	
	// Track attack vectors
	for _, vector := range attackVectors {
		session.AttackVectors[vector]++
	}
	
	// Track user agents and IPs
	userAgent := r.Header.Get("User-Agent")
	if userAgent != "" {
		session.UserAgents[userAgent]++
	}
	session.SourceIPs[sourceIP]++
	
	// Add to timeline
	event := research.AttackEvent{
		Timestamp: time.Now(),
		EventType: "http_request",
		Request: research.HTTPRequest{
			Method:             r.Method,
			Request:            r.URL.String(),
			UserAgent:          userAgent,
			AttackVectors:      attackVectors,
			RequestFingerprint: ra.Metrics.CalculateRequestFingerprint(r),
		},
	}
	session.AttackTimeline = append(session.AttackTimeline, event)
	
	// Update behavior profile
	session.BehaviorProfile = ra.calculateBehaviorProfile(session)
}

// GetSessionMetrics returns research metrics for a session
func (ra *ResearchAnalyzer) GetSessionMetrics(sessionID string) *research.ResearchMetrics {
	ra.sessionsMux.RLock()
	defer ra.sessionsMux.RUnlock()
	
	session, exists := ra.sessions[sessionID]
	if !exists {
		return nil
	}
	
	session.mutex.RLock()
	defer session.mutex.RUnlock()
	
	duration := session.LastActivity.Sub(session.StartTime)
	
	// Calculate persistence score (requests over time)
	persistenceScore := float64(session.RequestCount) / math.Max(duration.Hours(), 0.1)
	
	// Calculate engagement score based on variety and progression
	engagementScore := ra.calculateEngagementScore(session)
	
	// Determine technical skill level
	skillLevel := ra.assessTechnicalSkill(session)
	
	// Determine attack complexity
	complexity := ra.assessAttackComplexity(session)
	
	// Extract progression patterns
	progression := ra.extractAttackProgression(session)
	
	// Detect tools used
	tools := ra.detectToolsUsed(session)
	
	return &research.ResearchMetrics{
		SessionDuration:     duration,
		RequestCount:        session.RequestCount,
		AttackComplexity:    complexity,
		TechnicalSkillLevel: skillLevel,
		PersistenceScore:    persistenceScore,
		EngagementScore:     engagementScore,
		AttackProgression:   progression,
		ToolsDetected:       tools,
	}
}

// ExportSessionData exports session data for research analysis
func (ra *ResearchAnalyzer) ExportSessionData(sessionID string, format string) error {
	ra.sessionsMux.RLock()
	session, exists := ra.sessions[sessionID]
	ra.sessionsMux.RUnlock()
	
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}
	
	session.mutex.RLock()
	defer session.mutex.RUnlock()
	
	// Create timeline with summary
	timeline := research.AttackTimeline{
		SessionID: sessionID,
		StartTime: session.StartTime,
		EndTime:   session.LastActivity,
		Events:    session.AttackTimeline,
		Summary: research.AttackSummary{
			TotalRequests:       session.RequestCount,
			UniqueAttackTypes:   ra.getUniqueAttackTypes(session),
			HighestRiskScore:    ra.getHighestRiskScore(session.RiskScores),
			MostCommonTechnique: ra.getMostCommonAttackVector(session.AttackVectors),
			AttackerProfile:     session.BehaviorProfile,
		},
	}
	
	switch format {
	case "json":
		return ra.exportJSON(timeline, sessionID)
	case "csv":
		return ra.exportCSV(timeline, sessionID)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// Helper methods for analysis

func (ra *ResearchAnalyzer) determineAttackType(attackVectors, suspiciousPatterns []string) string {
	if len(attackVectors) == 0 {
		if len(suspiciousPatterns) > 0 {
			return "reconnaissance"
		}
		return "benign"
	}
	
	// Determine primary attack type
	vectorCounts := make(map[string]int)
	for _, vector := range attackVectors {
		vectorCounts[vector]++
	}
	
	maxCount := 0
	primaryType := ""
	for vector, count := range vectorCounts {
		if count > maxCount {
			maxCount = count
			primaryType = vector
		}
	}
	
	return primaryType
}

func (ra *ResearchAnalyzer) calculateConfidence(attackVectors, suspiciousPatterns []string, entropy float64) float64 {
	confidence := 0.0
	
	// Base confidence from attack vectors
	confidence += float64(len(attackVectors)) * 0.3
	
	// Additional confidence from suspicious patterns
	confidence += float64(len(suspiciousPatterns)) * 0.15
	
	// Entropy contribution
	if entropy > 6.0 {
		confidence += 0.2
	}
	
	// Normalize to 0-1 scale
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	return confidence
}

func (ra *ResearchAnalyzer) detectAnomalies(r *http.Request, body string, entropy float64) []string {
	var anomalies []string
	
	// High entropy content
	if entropy > 7.0 {
		anomalies = append(anomalies, "high_entropy_content")
	}
	
	// Unusual content length
	if len(body) > 100000 {
		anomalies = append(anomalies, "large_payload")
	}
	
	// Binary content in text fields
	if strings.Contains(r.Header.Get("Content-Type"), "text") && ra.containsBinaryData(body) {
		anomalies = append(anomalies, "binary_in_text")
	}
	
	// Unusual timing patterns (would need request timing data)
	// This is a placeholder for future implementation
	
	return anomalies
}

func (ra *ResearchAnalyzer) analyzePayload(body string, attackVectors []string) research.PayloadInfo {
	payloadType := "text"
	if body == "" {
		payloadType = "empty"
	} else if ra.containsBinaryData(body) {
		payloadType = "binary"
	}
	
	// Detect encoding schemes
	var encodingSchemes []string
	if strings.Contains(body, "%") {
		encodingSchemes = append(encodingSchemes, "url_encoding")
	}
	if ra.Metrics.containsBase64(body) {
		encodingSchemes = append(encodingSchemes, "base64")
	}
	if strings.Contains(body, "\\u") {
		encodingSchemes = append(encodingSchemes, "unicode_escape")
	}
	
	// Detect obfuscation
	obfuscated := len(encodingSchemes) > 1 || ra.Metrics.containsDoubleEncoding(body)
	
	// Extract malicious keywords
	keywords := ra.extractMaliciousKeywords(body)
	
	return research.PayloadInfo{
		Type:              payloadType,
		EncodingSchemes:   encodingSchemes,
		ObfuscationUsed:   obfuscated,
		MaliciousKeywords: keywords,
		Size:              int64(len(body)),
		Entropy:           ra.Metrics.CalculatePayloadEntropy(body),
	}
}

func (ra *ResearchAnalyzer) calculateBehaviorProfile(session *SessionTracker) research.AttackerProfile {
	// Assess skill level based on attack diversity and sophistication
	skillLevel := ra.assessTechnicalSkill(session)
	
	// Determine automation level
	automation := "unknown"
	if len(session.UserAgents) == 1 {
		ua := ""
		for agent := range session.UserAgents {
			ua = agent
			break
		}
		if ra.Metrics.isKnownScanner(ua) {
			automation = "automated"
		} else if strings.Contains(strings.ToLower(ua), "bot") {
			automation = "bot"
		} else {
			automation = "manual"
		}
	} else {
		automation = "mixed"
	}
	
	// Assess persistence
	persistence := "low"
	if session.RequestCount > 50 {
		persistence = "high"
	} else if session.RequestCount > 10 {
		persistence = "medium"
	}
	
	// Determine target focus
	targetFocus := ra.determineTargetFocus(session.AttackVectors)
	
	// Assess tactical approach
	tacticalApproach := ra.assessTacticalApproach(session)
	
	return research.AttackerProfile{
		SkillLevel:       skillLevel,
		Automation:       automation,
		Persistence:      persistence,
		TargetFocus:      targetFocus,
		TacticalApproach: tacticalApproach,
	}
}

func (ra *ResearchAnalyzer) assessTechnicalSkill(session *SessionTracker) string {
	// Count unique attack vectors
	uniqueVectors := len(session.AttackVectors)
	
	// Check for advanced techniques
	advancedCount := 0
	for vector := range session.AttackVectors {
		if vector == "xxe" || vector == "ssrf" || vector == "ldap_injection" {
			advancedCount++
		}
	}
	
	if advancedCount > 0 && uniqueVectors > 3 {
		return "advanced"
	} else if uniqueVectors > 2 {
		return "intermediate"
	} else if uniqueVectors > 0 {
		return "basic"
	}
	
	return "reconnaissance"
}

func (ra *ResearchAnalyzer) assessAttackComplexity(session *SessionTracker) string {
	uniqueVectors := len(session.AttackVectors)
	avgRiskScore := ra.calculateAverageRiskScore(session.RiskScores)
	
	if uniqueVectors > 4 && avgRiskScore > 7.0 {
		return "high"
	} else if uniqueVectors > 2 && avgRiskScore > 5.0 {
		return "medium"
	}
	
	return "low"
}

func (ra *ResearchAnalyzer) calculateEngagementScore(session *SessionTracker) float64 {
	// Base score from request count
	score := math.Min(float64(session.RequestCount)/10.0, 1.0)
	
	// Bonus for attack diversity
	diversity := float64(len(session.AttackVectors)) / 8.0 // Normalize to 8 possible vectors
	score += diversity * 0.5
	
	// Bonus for sustained activity
	duration := session.LastActivity.Sub(session.StartTime)
	if duration.Minutes() > 5 {
		score += 0.3
	}
	
	return math.Min(score, 1.0)
}

func (ra *ResearchAnalyzer) extractAttackProgression(session *SessionTracker) []string {
	var progression []string
	
	// Analyze timeline for progression patterns
	if len(session.AttackTimeline) > 0 {
		progression = append(progression, "initial_probe")
	}
	
	if session.RequestCount > 5 {
		progression = append(progression, "sustained_attack")
	}
	
	if len(session.AttackVectors) > 2 {
		progression = append(progression, "multi_vector_attack")
	}
	
	return progression
}

func (ra *ResearchAnalyzer) detectToolsUsed(session *SessionTracker) []string {
	var tools []string
	
	for userAgent := range session.UserAgents {
		lower := strings.ToLower(userAgent)
		if strings.Contains(lower, "sqlmap") {
			tools = append(tools, "sqlmap")
		} else if strings.Contains(lower, "nikto") {
			tools = append(tools, "nikto")
		} else if strings.Contains(lower, "burp") {
			tools = append(tools, "burp_suite")
		} else if strings.Contains(lower, "curl") {
			tools = append(tools, "curl")
		} else if strings.Contains(lower, "python") {
			tools = append(tools, "python_script")
		}
	}
	
	return tools
}

// Utility helper methods

func (ra *ResearchAnalyzer) containsBinaryData(data string) bool {
	for _, char := range data {
		if char < 32 && char != '\n' && char != '\r' && char != '\t' {
			return true
		}
	}
	return false
}

func (ra *ResearchAnalyzer) extractMaliciousKeywords(data string) []string {
	keywords := []string{
		"script", "alert", "eval", "exec", "system",
		"union", "select", "insert", "update", "delete",
		"passwd", "shadow", "cmd.exe", "powershell",
	}
	
	var found []string
	lower := strings.ToLower(data)
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			found = append(found, keyword)
		}
	}
	
	return found
}

func (ra *ResearchAnalyzer) getUniqueAttackTypes(session *SessionTracker) []string {
	types := make(map[string]bool)
	for vector := range session.AttackVectors {
		types[vector] = true
	}
	
	var result []string
	for vector := range types {
		result = append(result, vector)
	}
	
	return result
}

func (ra *ResearchAnalyzer) getHighestRiskScore(scores []float64) float64 {
	if len(scores) == 0 {
		return 0.0
	}
	
	max := scores[0]
	for _, score := range scores {
		if score > max {
			max = score
		}
	}
	
	return max
}

func (ra *ResearchAnalyzer) getMostCommonAttackVector(vectors map[string]int) string {
	if len(vectors) == 0 {
		return ""
	}
	
	maxCount := 0
	mostCommon := ""
	for vector, count := range vectors {
		if count > maxCount {
			maxCount = count
			mostCommon = vector
		}
	}
	
	return mostCommon
}

func (ra *ResearchAnalyzer) calculateAverageRiskScore(scores []float64) float64 {
	if len(scores) == 0 {
		return 0.0
	}
	
	sum := 0.0
	for _, score := range scores {
		sum += score
	}
	
	return sum / float64(len(scores))
}

func (ra *ResearchAnalyzer) determineTargetFocus(attackVectors map[string]int) []string {
	var focus []string
	
	if attackVectors["sql_injection"] > 0 {
		focus = append(focus, "database")
	}
	if attackVectors["xss"] > 0 {
		focus = append(focus, "client_side")
	}
	if attackVectors["command_injection"] > 0 {
		focus = append(focus, "system_commands")
	}
	if attackVectors["directory_traversal"] > 0 || attackVectors["file_inclusion"] > 0 {
		focus = append(focus, "file_system")
	}
	
	return focus
}

func (ra *ResearchAnalyzer) assessTacticalApproach(session *SessionTracker) string {
	if len(session.AttackVectors) > 3 {
		return "broad_scanning"
	} else if len(session.AttackVectors) > 1 {
		return "targeted_probing"
	} else if session.RequestCount > 10 {
		return "focused_exploitation"
	}
	
	return "reconnaissance"
}

// Export methods

func (ra *ResearchAnalyzer) exportJSON(timeline research.AttackTimeline, sessionID string) error {
	filename := filepath.Join(ra.dataDir, fmt.Sprintf("session_%s_%d.json", sessionID, time.Now().Unix()))
	
	data, err := json.MarshalIndent(timeline, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(filename, data, 0644)
}

func (ra *ResearchAnalyzer) exportCSV(timeline research.AttackTimeline, sessionID string) error {
	filename := filepath.Join(ra.dataDir, fmt.Sprintf("session_%s_%d.csv", sessionID, time.Now().Unix()))
	
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Write CSV header
	header := "timestamp,event_type,method,url,user_agent,attack_type,confidence,risk_score,attack_vectors\n"
	if _, err := file.WriteString(header); err != nil {
		return err
	}
	
	// Write events
	for _, event := range timeline.Events {
		line := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%.2f,%.2f,%s\n",
			event.Timestamp.Format(time.RFC3339),
			event.EventType,
			event.Request.Method,
			event.Request.Request,
			event.Request.UserAgent,
			event.Analysis.AttackType,
			event.Analysis.Confidence,
			event.Analysis.RiskScore,
			strings.Join(event.Request.AttackVectors, ";"),
		)
		if _, err := file.WriteString(line); err != nil {
			return err
		}
	}
	
	return nil
}

// CleanupSessions removes old inactive sessions
func (ra *ResearchAnalyzer) CleanupSessions(maxAge time.Duration) {
	ra.sessionsMux.Lock()
	defer ra.sessionsMux.Unlock()
	
	cutoff := time.Now().Add(-maxAge)
	for sessionID, session := range ra.sessions {
		if session.LastActivity.Before(cutoff) {
			delete(ra.sessions, sessionID)
		}
	}
	
	// Also cleanup MITRE campaigns
	if ra.MitreMapper != nil {
		ra.MitreMapper.CleanupOldCampaigns(maxAge)
	}
}

// GetMITREReport generates a MITRE ATT&CK report for a session
func (ra *ResearchAnalyzer) GetMITREReport(sessionID string) *mitre.MITREReport {
	if ra.MitreMapper == nil {
		return nil
	}
	return ra.MitreMapper.GenerateReport(sessionID)
}

// GetAttackCampaign returns MITRE attack campaign information for a session
func (ra *ResearchAnalyzer) GetAttackCampaign(sessionID string) (*mitre.AttackCampaign, bool) {
	if ra.MitreMapper == nil {
		return nil, false
	}
	return ra.MitreMapper.GetCampaign(sessionID)
}