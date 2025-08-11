package response

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ContextAnalyzer analyzes request context for intelligent response generation
type ContextAnalyzer struct {
	attackPatterns    map[string]AttackContext
	responseHistory   map[string][]ResponseRecord
	adaptiveThreshold float64
}

// AttackContext represents the context of an attack for response generation
type AttackContext struct {
	AttackType        string                 `json:"attack_type"`
	Sophistication    float64                `json:"sophistication"`
	Evasion           bool                   `json:"evasion"`
	Persistence       float64                `json:"persistence"`
	ThreatLevel       string                 `json:"threat_level"`
	AttackerProfile   string                 `json:"attacker_profile"`
	SessionHistory    []string               `json:"session_history"`
	TechnicalMarkers  []string               `json:"technical_markers"`
	MITRETechniques   []string               `json:"mitre_techniques"`
	BehavioralMetrics BehavioralContextMetrics `json:"behavioral_metrics"`
	Recommendations   []string               `json:"recommendations"`
}

// BehavioralContextMetrics represents behavioral context for response decisions
type BehavioralContextMetrics struct {
	RequestRate       float64 `json:"request_rate"`
	AttackDiversity   float64 `json:"attack_diversity"`
	TimingConsistency float64 `json:"timing_consistency"`
	AutomationLevel   string  `json:"automation_level"`
	SkillLevel        string  `json:"skill_level"`
	PersistenceLevel  string  `json:"persistence_level"`
}

// ResponseRecord tracks response effectiveness for learning
type ResponseRecord struct {
	Timestamp       time.Time            `json:"timestamp"`
	RequestID       string               `json:"request_id"`
	Context         AttackContext        `json:"context"`
	ResponseType    string               `json:"response_type"`
	ResponseContent map[string]interface{} `json:"response_content"`
	Effectiveness   float64              `json:"effectiveness"`
	AttackerReaction string              `json:"attacker_reaction"`
	FollowupRequests int                 `json:"followup_requests"`
	SessionContinued bool                `json:"session_continued"`
}

// ContextualResponse represents a context-aware response
type ContextualResponse struct {
	ResponseType     string                 `json:"response_type"`
	Content          map[string]interface{} `json:"content"`
	Headers          map[string]string      `json:"headers"`
	StatusCode       int                    `json:"status_code"`
	Complexity       float64                `json:"complexity"`
	Adaptiveness     float64                `json:"adaptiveness"`
	LearningValue    float64                `json:"learning_value"`
	ExpectedReaction string                 `json:"expected_reaction"`
	Justification    string                 `json:"justification"`
}

// NewContextAnalyzer creates a new context analyzer
func NewContextAnalyzer() *ContextAnalyzer {
	return &ContextAnalyzer{
		attackPatterns:    make(map[string]AttackContext),
		responseHistory:   make(map[string][]ResponseRecord),
		adaptiveThreshold: 0.3,
	}
}

// AnalyzeContext analyzes the full context of an HTTP request for response generation
func (ca *ContextAnalyzer) AnalyzeContext(r *http.Request, sessionID string, eventAnalysis *EventAnalysis) *AttackContext {
	context := &AttackContext{
		AttackType:      "unknown",
		Sophistication:  0.0,
		Evasion:        false,
		Persistence:    0.0,
		ThreatLevel:    "low",
		AttackerProfile: "unknown",
		SessionHistory:  []string{},
		TechnicalMarkers: []string{},
		MITRETechniques: []string{},
		BehavioralMetrics: BehavioralContextMetrics{},
		Recommendations: []string{},
	}

	// Extract context from event analysis
	if eventAnalysis != nil {
		context.AttackType = eventAnalysis.AttackType
		context.MITRETechniques = eventAnalysis.MITRETechniques
		
		// Determine sophistication from payload analysis
		if eventAnalysis.PayloadAnalysis.Complexity > 0 {
			context.Sophistication = eventAnalysis.PayloadAnalysis.Complexity
		}
		
		// Check for evasion techniques
		context.Evasion = ca.detectEvasionContext(r, eventAnalysis)
		
		// Extract technical markers
		context.TechnicalMarkers = ca.extractTechnicalMarkers(r, eventAnalysis)
	}

	// Analyze HTTP request characteristics
	ca.analyzeHTTPContext(r, context)
	
	// Determine threat level
	context.ThreatLevel = ca.assessThreatLevel(context)
	
	// Profile the attacker
	context.AttackerProfile = ca.profileAttacker(r, context)
	
	// Generate behavioral metrics
	context.BehavioralMetrics = ca.generateBehavioralContext(r, sessionID)
	
	// Generate recommendations
	context.Recommendations = ca.generateContextRecommendations(context)
	
	// Store context for learning
	ca.attackPatterns[sessionID] = *context
	
	return context
}

// detectEvasionContext detects evasion techniques from the request context
func (ca *ContextAnalyzer) detectEvasionContext(r *http.Request, eventAnalysis *EventAnalysis) bool {
	// Check for encoding variations
	if strings.Contains(r.URL.RawQuery, "%25") || strings.Contains(r.URL.RawQuery, "%2e%2e") {
		return true
	}
	
	// Check for case variation
	if ca.hasCaseVariationEvasion(r.URL.RawQuery) {
		return true
	}
	
	// Check for comment injection
	if strings.Contains(r.URL.RawQuery, "/*") || strings.Contains(r.URL.RawQuery, "--") {
		return true
	}
	
	// Check anomalies from event analysis
	if eventAnalysis != nil && len(eventAnalysis.Anomalies) > 0 {
		for _, anomaly := range eventAnalysis.Anomalies {
			if strings.Contains(strings.ToLower(anomaly), "evasion") || 
			   strings.Contains(strings.ToLower(anomaly), "encoding") {
				return true
			}
		}
	}
	
	return false
}

// extractTechnicalMarkers extracts technical markers from request and analysis
func (ca *ContextAnalyzer) extractTechnicalMarkers(r *http.Request, eventAnalysis *EventAnalysis) []string {
	markers := []string{}
	
	// User-Agent based markers
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	securityTools := []string{"sqlmap", "nikto", "burp", "nmap", "nuclei", "ffuf"}
	for _, tool := range securityTools {
		if strings.Contains(ua, tool) {
			markers = append(markers, fmt.Sprintf("tool:%s", tool))
		}
	}
	
	// Programming language markers
	langMarkers := []string{"python", "curl", "wget", "java", "go"}
	for _, lang := range langMarkers {
		if strings.Contains(ua, lang) {
			markers = append(markers, fmt.Sprintf("language:%s", lang))
		}
	}
	
	// Header-based markers
	if r.Header.Get("X-Forwarded-For") != "" {
		markers = append(markers, "header:x-forwarded-for")
	}
	
	// Custom headers
	customHeaders := 0
	standardHeaders := map[string]bool{
		"User-Agent": true, "Accept": true, "Accept-Language": true,
		"Accept-Encoding": true, "Connection": true, "Host": true,
		"Cache-Control": true, "Content-Type": true, "Content-Length": true,
	}
	
	for header := range r.Header {
		if !standardHeaders[header] {
			customHeaders++
		}
	}
	
	if customHeaders > 3 {
		markers = append(markers, "advanced:custom-headers")
	}
	
	// Payload complexity markers
	if eventAnalysis != nil {
		if eventAnalysis.PayloadAnalysis.Complexity > 0.7 {
			markers = append(markers, "payload:high-complexity")
		}
		if eventAnalysis.PayloadAnalysis.Entropy > 4.0 {
			markers = append(markers, "payload:high-entropy")
		}
	}
	
	return markers
}

// analyzeHTTPContext analyzes HTTP-specific context characteristics
func (ca *ContextAnalyzer) analyzeHTTPContext(r *http.Request, context *AttackContext) {
	// Method analysis
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		context.Sophistication += 0.2
	}
	
	// Path analysis
	suspiciousPaths := []string{"/admin", "/config", "/backup", "/test", "/.env"}
	for _, path := range suspiciousPaths {
		if strings.Contains(r.URL.Path, path) {
			context.Sophistication += 0.1
			break
		}
	}
	
	// Query parameter analysis
	if len(r.URL.RawQuery) > 100 {
		context.Sophistication += 0.2
	}
	
	// Multiple parameter analysis
	params := strings.Count(r.URL.RawQuery, "&")
	if params > 10 {
		context.Sophistication += 0.1
	}
	
	// Content-Type analysis
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart") || strings.Contains(contentType, "json") {
		context.Sophistication += 0.1
	}
}

// assessThreatLevel assesses the overall threat level based on context
func (ca *ContextAnalyzer) assessThreatLevel(context *AttackContext) string {
	score := 0.0
	
	// Sophistication weight
	score += context.Sophistication * 0.4
	
	// Evasion weight
	if context.Evasion {
		score += 0.3
	}
	
	// MITRE techniques weight
	if len(context.MITRETechniques) > 0 {
		score += float64(len(context.MITRETechniques)) * 0.1
	}
	
	// Technical markers weight
	advancedMarkers := 0
	for _, marker := range context.TechnicalMarkers {
		if strings.Contains(marker, "advanced:") || strings.Contains(marker, "tool:") {
			advancedMarkers++
		}
	}
	score += float64(advancedMarkers) * 0.05
	
	// Threat level classification
	if score > 0.8 {
		return "critical"
	} else if score > 0.6 {
		return "high"
	} else if score > 0.4 {
		return "medium"
	} else {
		return "low"
	}
}

// profileAttacker profiles the attacker based on context
func (ca *ContextAnalyzer) profileAttacker(r *http.Request, context *AttackContext) string {
	// Check for security tool signatures
	hasSecurityTools := false
	for _, marker := range context.TechnicalMarkers {
		if strings.HasPrefix(marker, "tool:") {
			hasSecurityTools = true
			break
		}
	}
	
	// Sophistication-based profiling
	if hasSecurityTools && context.Sophistication > 0.7 {
		return "professional_penetration_tester"
	} else if hasSecurityTools && context.Sophistication < 0.4 {
		return "script_kiddie"
	} else if context.Sophistication > 0.6 && context.Evasion {
		return "skilled_manual_attacker"
	} else if hasSecurityTools {
		return "automated_scanner"
	} else {
		return "opportunistic_attacker"
	}
}

// generateBehavioralContext generates behavioral context metrics
func (ca *ContextAnalyzer) generateBehavioralContext(r *http.Request, sessionID string) BehavioralContextMetrics {
	// This would typically integrate with the behavioral profiler
	// For now, provide basic analysis
	
	metrics := BehavioralContextMetrics{
		RequestRate:       1.0, // Default single request rate
		AttackDiversity:   0.0,
		TimingConsistency: 1.0, // Default high consistency for single request
		AutomationLevel:   "unknown",
		SkillLevel:        "unknown",
		PersistenceLevel:  "unknown",
	}
	
	// Analyze User-Agent for automation indicators
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	if strings.Contains(ua, "python") || strings.Contains(ua, "curl") || strings.Contains(ua, "wget") {
		metrics.AutomationLevel = "automated"
	} else if strings.Contains(ua, "mozilla") || strings.Contains(ua, "chrome") {
		metrics.AutomationLevel = "manual"
	}
	
	return metrics
}

// generateContextRecommendations generates context-specific recommendations
func (ca *ContextAnalyzer) generateContextRecommendations(context *AttackContext) []string {
	recommendations := []string{}
	
	// Threat level based recommendations
	switch context.ThreatLevel {
	case "critical":
		recommendations = append(recommendations, "Immediate threat response required")
		recommendations = append(recommendations, "Consider IP blocking and advanced monitoring")
	case "high":
		recommendations = append(recommendations, "Enhanced monitoring and response")
		recommendations = append(recommendations, "Deploy additional security measures")
	case "medium":
		recommendations = append(recommendations, "Monitor for escalation patterns")
	}
	
	// Evasion-based recommendations
	if context.Evasion {
		recommendations = append(recommendations, "Update WAF rules for evasion techniques")
		recommendations = append(recommendations, "Implement advanced pattern detection")
	}
	
	// Attacker profile recommendations
	switch context.AttackerProfile {
	case "professional_penetration_tester":
		recommendations = append(recommendations, "Deploy advanced behavioral analysis")
		recommendations = append(recommendations, "Implement sophisticated honeypot responses")
	case "script_kiddie":
		recommendations = append(recommendations, "Basic rate limiting may be effective")
		recommendations = append(recommendations, "Standard security measures should suffice")
	case "automated_scanner":
		recommendations = append(recommendations, "Implement scanner-specific countermeasures")
		recommendations = append(recommendations, "Deploy rate limiting and CAPTCHA")
	}
	
	return recommendations
}

// RecordResponse records a response for learning and adaptation
func (ca *ContextAnalyzer) RecordResponse(sessionID string, requestID string, response *ContextualResponse, effectiveness float64) {
	if context, exists := ca.attackPatterns[sessionID]; exists {
		record := ResponseRecord{
			Timestamp:        time.Now(),
			RequestID:        requestID,
			Context:          context,
			ResponseType:     response.ResponseType,
			ResponseContent:  response.Content,
			Effectiveness:    effectiveness,
			AttackerReaction: "unknown", // Would be updated based on follow-up analysis
			FollowupRequests: 0,         // Would be updated based on session continuation
			SessionContinued: false,     // Would be updated based on session analysis
		}
		
		ca.responseHistory[sessionID] = append(ca.responseHistory[sessionID], record)
	}
}

// GetSessionContext returns the attack context for a session
func (ca *ContextAnalyzer) GetSessionContext(sessionID string) (*AttackContext, bool) {
	context, exists := ca.attackPatterns[sessionID]
	return &context, exists
}

// GetResponseHistory returns the response history for a session
func (ca *ContextAnalyzer) GetResponseHistory(sessionID string) []ResponseRecord {
	if history, exists := ca.responseHistory[sessionID]; exists {
		return history
	}
	return []ResponseRecord{}
}

// AnalyzeResponseEffectiveness analyzes the effectiveness of previous responses
func (ca *ContextAnalyzer) AnalyzeResponseEffectiveness(sessionID string) float64 {
	history := ca.GetResponseHistory(sessionID)
	if len(history) == 0 {
		return 0.0
	}
	
	totalEffectiveness := 0.0
	for _, record := range history {
		totalEffectiveness += record.Effectiveness
	}
	
	return totalEffectiveness / float64(len(history))
}

// Helper methods

func (ca *ContextAnalyzer) hasCaseVariationEvasion(query string) bool {
	keywords := []string{"select", "union", "insert", "script", "alert"}
	
	for _, keyword := range keywords {
		if strings.Contains(strings.ToLower(query), keyword) {
			// Check for mixed case
			if !strings.Contains(query, keyword) && !strings.Contains(query, strings.ToUpper(keyword)) {
				return true
			}
		}
	}
	
	return false
}

// ExportContextData exports context analysis data for research
func (ca *ContextAnalyzer) ExportContextData() ([]byte, error) {
	exportData := struct {
		AttackPatterns  map[string]AttackContext        `json:"attack_patterns"`
		ResponseHistory map[string][]ResponseRecord     `json:"response_history"`
		ExportedAt      time.Time                       `json:"exported_at"`
	}{
		AttackPatterns:  ca.attackPatterns,
		ResponseHistory: ca.responseHistory,
		ExportedAt:      time.Now(),
	}
	
	return json.MarshalIndent(exportData, "", "  ")
}