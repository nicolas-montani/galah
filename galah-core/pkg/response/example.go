package response

import (
	"net/http"
	"strings"
)

// ExampleUsage demonstrates how to use the Context-Aware Response Generation Framework
func ExampleUsage() {
	// Initialize the response manager (integrates all components)
	responseManager := NewResponseManager()
	
	// Enable adaptive learning and set appropriate parameters
	responseManager.SetLearningEnabled(true)
	responseManager.SetAdaptiveMode(true)
	
	// Example: Create a mock HTTP request that might contain an attack
	request := &http.Request{
		Method: "GET",
		URL:    nil, // Would normally be parsed
		Header: make(http.Header),
	}
	request.Header.Set("User-Agent", "sqlmap/1.0")
	
	// Create a mock event analysis (would normally come from analytics pipeline)
	eventAnalysis := &EventAnalysis{
		AttackType:      "sql_injection",
		Confidence:      0.85,
		MITRETechniques: []string{"T1190"},
		PayloadAnalysis: PayloadInfo{
			Length:     45,
			Entropy:    3.2,
			Complexity: 0.7,
			Type:       "sql",
			Patterns:   []string{"union", "select"},
		},
		RiskScore: 7.5,
	}
	
	// Generate a context-aware response
	sessionID := "session_12345"
	response, err := responseManager.GenerateContextAwareResponse(request, sessionID, eventAnalysis)
	if err != nil {
		// Handle error
		return
	}
	
	// The response will be intelligently crafted based on:
	// - Attack sophistication (detected SQLMap usage)
	// - Threat level (high risk score)
	// - MITRE techniques (T1190 - Exploit Public-Facing Application)
	// - Attacker profiling (professional tool usage)
	
	// Example response characteristics:
	// - ResponseType: "complex_honeypot" (for sophisticated attacker)
	// - High complexity content with realistic database errors
	// - Adaptive headers and status codes
	// - Learning value captured for future improvements
	
	_ = response // Use the response to generate HTTP output
}

// IntegrationWithExistingGalah shows how to integrate with existing Galah service
func IntegrationWithExistingGalah(r *http.Request, sessionID string) map[string]interface{} {
	// Initialize response manager
	rm := NewResponseManager()
	
	// Analyze the request for potential attacks
	// (This would integrate with existing Galah analytics)
	eventAnalysis := analyzeRequestForThreats(r)
	
	// Generate context-aware response
	if eventAnalysis != nil && eventAnalysis.RiskScore > 3.0 {
		contextResponse, err := rm.GenerateContextAwareResponse(r, sessionID, eventAnalysis)
		if err != nil {
			// Fall back to standard Galah response generation
			return generateStandardResponse()
		}
		
		// Return the intelligent response content
		return contextResponse.Content
	}
	
	// For low-risk requests, use standard response
	return generateStandardResponse()
}

// Helper functions for integration example

func analyzeRequestForThreats(r *http.Request) *EventAnalysis {
	// Simplified threat analysis (would integrate with full analytics pipeline)
	riskScore := 0.0
	attackType := "benign"
	techniques := []string{}
	
	// Check for common attack patterns
	query := r.URL.RawQuery
	if strings.Contains(query, "union") || strings.Contains(query, "select") {
		attackType = "sql_injection"
		riskScore = 6.0
		techniques = append(techniques, "T1190")
	}
	
	if strings.Contains(query, "<script>") || strings.Contains(query, "javascript:") {
		attackType = "xss"
		riskScore = 5.0
		techniques = append(techniques, "T1190")
	}
	
	if riskScore > 0 {
		return &EventAnalysis{
			AttackType:      attackType,
			Confidence:      0.7,
			MITRETechniques: techniques,
			RiskScore:       riskScore,
			PayloadAnalysis: PayloadInfo{
				Length:     len(query),
				Complexity: riskScore / 10.0,
			},
		}
	}
	
	return nil
}

func generateStandardResponse() map[string]interface{} {
	return map[string]interface{}{
		"status":  "success",
		"message": "Request processed",
		"data":    map[string]interface{}{"result": "ok"},
	}
}