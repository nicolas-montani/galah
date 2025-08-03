package logger

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/0x4d31/galah/pkg/analytics"
	"github.com/0x4d31/galah/pkg/llm"
	"github.com/0x4d31/galah/pkg/research"
	"github.com/0x4d31/galah/pkg/suricata"
)

// ResearchLogger extends the basic logger with research-focused analytics
type ResearchLogger struct {
	*Logger
	analyzer *analytics.ResearchAnalyzer
}

// NewResearchLogger creates a new research-enhanced logger
func NewResearchLogger(eventLogFile string, modelConfig llm.Config, analyzer *analytics.ResearchAnalyzer, l *Logger) *ResearchLogger {
	return &ResearchLogger{
		Logger:   l,
		analyzer: analyzer,
	}
}

// LogEventWithResearch logs an event with comprehensive research analytics
func (rl *ResearchLogger) LogEventWithResearch(r *http.Request, resp llm.JSONResponse, port, respSource string, suricataMatches []suricata.Rule, processingTime time.Duration) {
	// Read body for analysis
	bodyBytes, _ := io.ReadAll(r.Body)
	body := string(bodyBytes)
	
	// Get session ID
	sessionID := rl.getSessionID(r)
	srcIP := rl.getSourceIP(r)
	
	// Perform research analysis
	analysis := rl.analyzer.AnalyzeRequest(r, body, sessionID, srcIP)
	
	// Calculate additional research metrics
	requestSize := int64(len(body))
	contentType := r.Header.Get("Content-Type")
	requestFingerprint := rl.analyzer.Metrics.CalculateRequestFingerprint(r)
	
	// Create enhanced HTTP request with research data
	fields := rl.commonFields(r, port)
	
	// Enhance HTTPRequest with research fields
	if httpReq, ok := fields["httpRequest"].(HTTPRequest); ok {
		// Convert to research HTTPRequest with additional fields
		researchReq := research.HTTPRequest{
			Body:                httpReq.Body,
			BodySha256:          httpReq.BodySha256,
			Headers:             httpReq.Headers,
			HeadersSorted:       httpReq.HeadersSorted,
			HeadersSortedSha256: httpReq.HeadersSortedSha256,
			Method:              httpReq.Method,
			ProtocolVersion:     httpReq.ProtocolVersion,
			Request:             httpReq.Request,
			SessionID:           httpReq.SessionID,
			UserAgent:           httpReq.UserAgent,
			RequestSize:         requestSize,
			ContentType:         contentType,
			RequestFingerprint:  requestFingerprint,
			AttackVectors:       analysis.PayloadAnalysis.MaliciousKeywords,
			SuspiciousPatterns:  analysis.Anomalies,
		}
		fields["httpRequest"] = researchReq
	}
	
	// Enhance response metadata with research data
	responseMetadata := ResponseMetadata{
		GenerationSource:  respSource,
		ProcessingTime:    processingTime,
		CacheHit:         respSource == "cache",
		ResponseQuality:  rl.calculateResponseQuality(resp, analysis),
		ContextAdaptation: rl.determineContextAdaptation(analysis),
	}
	
	if respSource == "llm" {
		responseMetadata.Info = LLMInfo{
			Provider:    rl.LLMConfig.Provider,
			Model:       rl.LLMConfig.Model,
			Temperature: rl.LLMConfig.Temperature,
		}
	}
	
	fields["responseMetadata"] = responseMetadata
	fields["httpResponse"] = resp
	
	// Add research-specific analysis
	fields["eventAnalysis"] = analysis
	fields["researchMetrics"] = rl.analyzer.GetSessionMetrics(sessionID)
	
	// Include Suricata matches with enhanced analysis
	if len(suricataMatches) > 0 {
		var matches []map[string]interface{}
		for _, m := range suricataMatches {
			matchInfo := map[string]interface{}{
				"sid":        m.SID,
				"msg":        m.Msg,
				"confidence": rl.calculateSuricataConfidence(m),
				"severity":   rl.assessSuricataSeverity(m),
			}
			matches = append(matches, matchInfo)
		}
		fields["suricataMatches"] = matches
	}
	
	// Add attack timeline event
	event := research.AttackEvent{
		Timestamp: time.Now(),
		EventType: "http_request",
		Request:   fields["httpRequest"].(research.HTTPRequest),
		Response:  rl.convertResponseToMap(resp),
		Analysis:  *analysis,
	}
	fields["attackEvent"] = event
	
	// Log the enhanced event
	rl.EventLogger.Info("successfulResponse", mapToArgs(fields)...)
}

// LogErrorWithResearch logs an error with research context
func (rl *ResearchLogger) LogErrorWithResearch(r *http.Request, resp, port string, err error, processingTime time.Duration) {
	// Read body for analysis
	bodyBytes, _ := io.ReadAll(r.Body)
	body := string(bodyBytes)
	
	// Get session info
	sessionID := rl.getSessionID(r)
	srcIP := rl.getSourceIP(r)
	
	// Perform basic analysis even for errors
	analysis := rl.analyzer.AnalyzeRequest(r, body, sessionID, srcIP)
	
	fields := rl.commonFields(r, port)
	fields["error"] = errorFields(err, resp)
	
	// Enhanced response metadata for errors
	responseMetadata := ResponseMetadata{
		GenerationSource: "error",
		ProcessingTime:   processingTime,
		CacheHit:        false,
		Info: LLMInfo{
			Provider:    rl.LLMConfig.Provider,
			Model:       rl.LLMConfig.Model,
			Temperature: rl.LLMConfig.Temperature,
		},
	}
	fields["responseMetadata"] = responseMetadata
	
	// Add analysis data even for errors
	fields["eventAnalysis"] = analysis
	fields["researchMetrics"] = rl.analyzer.GetSessionMetrics(sessionID)
	
	rl.EventLogger.Error("failedResponse: returned 500 internal server error", mapToArgs(fields)...)
}

// Helper methods for research logging

func (rl *ResearchLogger) getSessionID(r *http.Request) string {
	// Extract session ID from the existing commonFields logic
	// This is a simplified version - in practice, you'd integrate with the Sessionizer
	return "session_" + rl.getSourceIP(r) + "_" + strconv.FormatInt(time.Now().Unix(), 10)
}

func (rl *ResearchLogger) getSourceIP(r *http.Request) string {
	// Extract source IP from remote address
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) > 0 {
		return parts[0]
	}
	return r.RemoteAddr
}

func (rl *ResearchLogger) calculateResponseQuality(resp llm.JSONResponse, analysis *research.EventAnalysis) float64 {
	// Calculate response quality based on various factors
	quality := 0.5 // Base quality
	
	// Increase quality if response seems appropriate for attack type
	if analysis.AttackType != "" && analysis.AttackType != "benign" {
		if len(resp.Body) > 100 {
			quality += 0.2 // Response has substantial content
		}
		if len(resp.Headers) > 2 {
			quality += 0.1 // Response has realistic headers
		}
	}
	
	// Adjust based on confidence in attack detection
	quality += analysis.Confidence * 0.2
	
	// Cap at 1.0
	if quality > 1.0 {
		quality = 1.0
	}
	
	return quality
}

func (rl *ResearchLogger) determineContextAdaptation(analysis *research.EventAnalysis) string {
	if analysis.AttackType == "" || analysis.AttackType == "benign" {
		return "generic"
	}
	
	// Determine what kind of context adaptation was used
	switch analysis.AttackType {
	case "sql_injection":
		return "database_application"
	case "xss":
		return "web_application"
	case "command_injection":
		return "system_interface"
	case "directory_traversal", "file_inclusion":
		return "file_server"
	default:
		return "attack_aware"
	}
}

func (rl *ResearchLogger) calculateSuricataConfidence(rule suricata.Rule) float64 {
	// Calculate confidence based on rule characteristics
	confidence := 0.7 // Base confidence for Suricata matches
	
	// Increase confidence for more specific rules
	if strings.Contains(rule.Msg, "SPECIFIC") {
		confidence += 0.2
	}
	
	// Decrease for generic rules
	if strings.Contains(rule.Msg, "Generic") || strings.Contains(rule.Msg, "GENERIC") {
		confidence -= 0.2
	}
	
	// Ensure confidence is between 0 and 1
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}
	
	return confidence
}

func (rl *ResearchLogger) assessSuricataSeverity(rule suricata.Rule) string {
	msg := strings.ToLower(rule.Msg)
	
	// High severity indicators
	if strings.Contains(msg, "critical") || strings.Contains(msg, "exploit") || 
	   strings.Contains(msg, "malware") || strings.Contains(msg, "backdoor") {
		return "high"
	}
	
	// Medium severity indicators
	if strings.Contains(msg, "attack") || strings.Contains(msg, "injection") ||
	   strings.Contains(msg, "traversal") || strings.Contains(msg, "bypass") {
		return "medium"
	}
	
	// Low severity (reconnaissance, scanning, etc.)
	if strings.Contains(msg, "scan") || strings.Contains(msg, "probe") ||
	   strings.Contains(msg, "recon") {
		return "low"
	}
	
	return "medium" // Default severity
}

func (rl *ResearchLogger) convertResponseToMap(resp llm.JSONResponse) map[string]interface{} {
	result := make(map[string]interface{})
	result["headers"] = resp.Headers
	result["body"] = resp.Body
	return result
}

// ExportSessionData exports session data in various formats for research
func (rl *ResearchLogger) ExportSessionData(sessionID, format string) error {
	return rl.analyzer.ExportSessionData(sessionID, format)
}

// GetSessionTimeline returns the attack timeline for a session
func (rl *ResearchLogger) GetSessionTimeline(sessionID string) *research.AttackTimeline {
	metrics := rl.analyzer.GetSessionMetrics(sessionID)
	if metrics == nil {
		return nil
	}
	
	// Create timeline from session data
	// This would be enhanced with actual timeline data from the analyzer
	return &research.AttackTimeline{
		SessionID: sessionID,
		StartTime: time.Now(), // Would be actual start time
		Events:    []research.AttackEvent{}, // Would be populated from session data
		Summary: research.AttackSummary{
			TotalRequests: metrics.RequestCount,
			AttackerProfile: research.AttackerProfile{
				SkillLevel: metrics.TechnicalSkillLevel,
			},
		},
	}
}

// CleanupOldSessions removes old session data to prevent memory leaks
func (rl *ResearchLogger) CleanupOldSessions(maxAge time.Duration) {
	rl.analyzer.CleanupSessions(maxAge)
}