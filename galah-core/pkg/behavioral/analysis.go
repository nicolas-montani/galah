package behavioral

import (
	"crypto/sha256"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
)

// detectTechnicalMarkers identifies technical indicators of skill/tools
func (ap *AttackerProfiler) detectTechnicalMarkers(r *http.Request, signature RequestSignature) []TechnicalMarker {
	var markers []TechnicalMarker
	
	// Tool signatures in User-Agent
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	toolMarkers := map[string]string{
		"sqlmap":     "Automated SQL injection tool",
		"nikto":      "Web vulnerability scanner",
		"burp":       "Professional web security testing",
		"nmap":       "Network reconnaissance tool",
		"gobuster":   "Directory/file brute forcer",
		"wpscan":     "WordPress security scanner",
		"nuclei":     "Vulnerability scanner",
		"masscan":    "Internet-scale port scanner",
		"zap":        "OWASP security testing proxy",
		"acunetix":   "Commercial vulnerability scanner",
	}
	
	for tool, desc := range toolMarkers {
		if strings.Contains(ua, tool) {
			markers = append(markers, TechnicalMarker{
				Type:        "tool_signature",
				Description: desc,
				Confidence:  0.9,
				Evidence:    fmt.Sprintf("User-Agent: %s", tool),
				Timestamp:   time.Now(),
			})
		}
	}
	
	// Encoding techniques
	markers = append(markers, ap.detectEncodingTechniques(r)...)
	
	// Evasion methods
	markers = append(markers, ap.detectEvasionMethods(r)...)
	
	// Advanced techniques
	markers = append(markers, ap.detectAdvancedTechniques(r)...)
	
	return markers
}

// detectEncodingTechniques detects various encoding/obfuscation techniques
func (ap *AttackerProfiler) detectEncodingTechniques(r *http.Request) []TechnicalMarker {
	var markers []TechnicalMarker
	
	fullURL := r.URL.String()
	
	// URL encoding patterns
	if strings.Contains(fullURL, "%20") && strings.Contains(fullURL, "%3C") {
		markers = append(markers, TechnicalMarker{
			Type:        "encoding_technique",
			Description: "URL encoding usage",
			Confidence:  0.6,
			Evidence:    "Multiple URL encoded characters",
			Timestamp:   time.Now(),
		})
	}
	
	// Double encoding
	if strings.Contains(fullURL, "%25") {
		markers = append(markers, TechnicalMarker{
			Type:        "encoding_technique",
			Description: "Double URL encoding",
			Confidence:  0.8,
			Evidence:    "Double encoded characters detected",
			Timestamp:   time.Now(),
		})
	}
	
	// Unicode escaping
	if strings.Contains(fullURL, "\\u") || strings.Contains(fullURL, "%u") {
		markers = append(markers, TechnicalMarker{
			Type:        "encoding_technique",
			Description: "Unicode escaping",
			Confidence:  0.7,
			Evidence:    "Unicode escape sequences",
			Timestamp:   time.Now(),
		})
	}
	
	// Base64 patterns (simplified detection)
	if ap.containsBase64Like(fullURL) {
		markers = append(markers, TechnicalMarker{
			Type:        "encoding_technique",
			Description: "Base64 encoding",
			Confidence:  0.5,
			Evidence:    "Base64-like strings detected",
			Timestamp:   time.Now(),
		})
	}
	
	return markers
}

// detectEvasionMethods detects various evasion techniques
func (ap *AttackerProfiler) detectEvasionMethods(r *http.Request) []TechnicalMarker {
	var markers []TechnicalMarker
	
	// Case variation evasion
	if ap.hasCaseVariation(r.URL.RawQuery) {
		markers = append(markers, TechnicalMarker{
			Type:        "evasion_method",
			Description: "Case variation evasion",
			Confidence:  0.6,
			Evidence:    "Mixed case in keywords",
			Timestamp:   time.Now(),
		})
	}
	
	// Comment injection
	if strings.Contains(r.URL.RawQuery, "/*") || strings.Contains(r.URL.RawQuery, "--") {
		markers = append(markers, TechnicalMarker{
			Type:        "evasion_method",
			Description: "Comment injection evasion",
			Confidence:  0.7,
			Evidence:    "SQL/HTML comments in payload",
			Timestamp:   time.Now(),
		})
	}
	
	// Null byte injection
	if strings.Contains(r.URL.RawQuery, "%00") || strings.Contains(r.URL.RawQuery, "\\x00") {
		markers = append(markers, TechnicalMarker{
			Type:        "evasion_method",
			Description: "Null byte injection",
			Confidence:  0.8,
			Evidence:    "Null bytes in payload",
			Timestamp:   time.Now(),
		})
	}
	
	// WAF evasion headers
	evasionHeaders := []string{
		"X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
		"X-Remote-IP", "X-Client-IP", "Client-IP",
	}
	
	for _, header := range evasionHeaders {
		if r.Header.Get(header) != "" {
			markers = append(markers, TechnicalMarker{
				Type:        "evasion_method",
				Description: "IP obfuscation headers",
				Confidence:  0.5,
				Evidence:    fmt.Sprintf("Header: %s", header),
				Timestamp:   time.Now(),
			})
			break // Only mark once for IP obfuscation
		}
	}
	
	return markers
}

// detectAdvancedTechniques detects sophisticated attack techniques
func (ap *AttackerProfiler) detectAdvancedTechniques(r *http.Request) []TechnicalMarker {
	var markers []TechnicalMarker
	
	// Time-based attack patterns (detected through timing)
	// This would require historical timing data
	
	// Blind injection techniques
	if ap.hasBlindInjectionPattern(r.URL.RawQuery) {
		markers = append(markers, TechnicalMarker{
			Type:        "advanced_technique",
			Description: "Blind injection techniques",
			Confidence:  0.8,
			Evidence:    "Boolean-based blind injection patterns",
			Timestamp:   time.Now(),
		})
	}
	
	// Polyglot payloads (work across multiple contexts)
	if ap.hasPolyglotPattern(r.URL.RawQuery) {
		markers = append(markers, TechnicalMarker{
			Type:        "advanced_technique",
			Description: "Polyglot payload",
			Confidence:  0.9,
			Evidence:    "Multi-context payload detected",
			Timestamp:   time.Now(),
		})
	}
	
	// Custom header fingerprinting
	if ap.hasCustomFingerprinting(r) {
		markers = append(markers, TechnicalMarker{
			Type:        "advanced_technique",
			Description: "Custom fingerprinting",
			Confidence:  0.7,
			Evidence:    "Unusual header combinations",
			Timestamp:   time.Now(),
		})
	}
	
	return markers
}

// updateProfilingScores updates the various profiling scores
func (ap *AttackerProfiler) updateProfilingScores(profile *SessionProfile) {
	profile.ConsistencyScore = ap.calculateConsistencyScore(profile)
	profile.SophisticationScore = ap.calculateSophisticationScore(profile)
	profile.PersistenceScore = ap.calculatePersistenceScore(profile)
	profile.ProfileUpdated = time.Now()
}

// calculateConsistencyScore calculates behavioral consistency
func (ap *AttackerProfiler) calculateConsistencyScore(profile *SessionProfile) float64 {
	if len(profile.RequestSequence) < 3 {
		return 1.0 // Default high consistency for new sessions
	}
	
	// Analyze consistency across multiple dimensions
	timingConsistency := profile.BehaviorMetrics.TimingConsistency
	
	// User-Agent consistency
	uaConsistency := ap.calculateUserAgentConsistency(profile)
	
	// Attack pattern consistency
	patternConsistency := ap.calculateAttackPatternConsistency(profile)
	
	// Weighted average
	return (timingConsistency*0.4 + uaConsistency*0.3 + patternConsistency*0.3)
}

// calculateSophisticationScore calculates attacker sophistication
func (ap *AttackerProfiler) calculateSophisticationScore(profile *SessionProfile) float64 {
	score := 0.0
	
	// Base score from attack diversity
	score += profile.BehaviorMetrics.AttackDiversity * 0.3
	
	// Technical markers contribution
	advancedMarkers := 0
	for _, marker := range profile.TechnicalMarkers {
		if marker.Type == "advanced_technique" {
			advancedMarkers++
		}
	}
	score += math.Min(float64(advancedMarkers)*0.2, 0.4)
	
	// Evasion techniques
	evasionMarkers := 0
	for _, marker := range profile.TechnicalMarkers {
		if marker.Type == "evasion_method" {
			evasionMarkers++
		}
	}
	score += math.Min(float64(evasionMarkers)*0.1, 0.3)
	
	// Progression complexity
	score += profile.BehaviorMetrics.ProgressionComplexity * 0.2
	
	// Normalize to 0-1
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

// calculatePersistenceScore calculates persistence behavior
func (ap *AttackerProfiler) calculatePersistenceScore(profile *SessionProfile) float64 {
	return profile.BehaviorMetrics.PersistenceIndicator
}

// generateFingerprint creates a behavioral fingerprint
func (ap *AttackerProfiler) generateFingerprint(profile *SessionProfile) *BehavioralFingerprint {
	// Extract patterns
	requestPatterns := ap.extractRequestPatterns(profile)
	headerPatterns := ap.extractHeaderPatterns(profile)
	attackSequence := ap.extractAttackSequence(profile)
	
	// Calculate timing profile
	timingProfile := ap.calculateTimingProfile(profile)
	
	// Create characteristics map
	characteristics := map[string]float64{
		"request_rate":      profile.BehaviorMetrics.RequestRate,
		"attack_diversity":  profile.BehaviorMetrics.AttackDiversity,
		"timing_consistency": profile.BehaviorMetrics.TimingConsistency,
		"sophistication":    profile.SophisticationScore,
		"consistency":       profile.ConsistencyScore,
	}
	
	// Generate hash
	hash := ap.generateFingerprintHash(requestPatterns, headerPatterns, attackSequence)
	
	// Check if fingerprint exists
	if existing, exists := ap.fingerprints[hash]; exists {
		existing.LastSeen = time.Now()
		existing.SeenCount++
		existing.AssociatedIPs = ap.addUniqueIP(existing.AssociatedIPs, profile.SourceIP)
		return existing
	}
	
	// Create new fingerprint
	fingerprint := &BehavioralFingerprint{
		Hash:            hash,
		RequestPatterns: requestPatterns,
		TimingProfile:   timingProfile,
		HeaderPatterns:  headerPatterns,
		AttackSequence:  attackSequence,
		Characteristics: characteristics,
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
		SeenCount:       1,
		AssociatedIPs:   []string{profile.SourceIP},
	}
	
	ap.fingerprints[hash] = fingerprint
	return fingerprint
}

// Classification methods

func (ap *AttackerProfiler) calculateProfileConfidence(profile *SessionProfile) float64 {
	// Base confidence from number of requests
	baseConfidence := math.Min(float64(len(profile.RequestSequence))/10.0, 1.0)
	
	// Boost from technical markers
	markerBoost := math.Min(float64(len(profile.TechnicalMarkers))*0.1, 0.3)
	
	// Consistency bonus
	consistencyBonus := profile.ConsistencyScore * 0.2
	
	confidence := baseConfidence + markerBoost + consistencyBonus
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	return confidence
}

func (ap *AttackerProfiler) classifyAttackerType(profile *SessionProfile) string {
	// Analyze technical markers for tool usage
	hasSecurityTools := false
	hasBrowserSignature := false
	
	for _, marker := range profile.TechnicalMarkers {
		if marker.Type == "tool_signature" {
			if strings.Contains(marker.Description, "scanner") || 
			   strings.Contains(marker.Description, "injection") {
				hasSecurityTools = true
			}
		}
	}
	
	// Check for browser-like behavior
	if len(profile.RequestSequence) > 0 {
		// This would need access to the original request - simplified for now
		hasBrowserSignature = true // Placeholder
	}
	
	// Classification logic
	if hasSecurityTools && profile.SophisticationScore > 0.7 {
		return "professional_penetration_tester"
	} else if hasSecurityTools {
		return "script_kiddie"
	} else if profile.BehaviorMetrics.AttackDiversity > 2.0 && profile.SophisticationScore > 0.6 {
		return "skilled_manual_attacker"
	} else if profile.BehaviorMetrics.TimingConsistency > 0.8 && profile.BehaviorMetrics.RequestRate > 5.0 {
		return "automated_bot"
	} else if hasBrowserSignature && profile.BehaviorMetrics.RequestRate < 1.0 {
		return "manual_human_attacker"
	} else {
		return "unknown"
	}
}

func (ap *AttackerProfiler) assessSkillLevel(profile *SessionProfile) string {
	score := profile.SophisticationScore
	
	if score > 0.8 {
		return "expert"
	} else if score > 0.6 {
		return "advanced"
	} else if score > 0.4 {
		return "intermediate"
	} else if score > 0.2 {
		return "beginner"
	} else {
		return "script_kiddie"
	}
}

func (ap *AttackerProfiler) assessAutomationLevel(profile *SessionProfile) string {
	// High request rate + high timing consistency = likely automated
	if profile.BehaviorMetrics.RequestRate > 10.0 && profile.BehaviorMetrics.TimingConsistency > 0.9 {
		return "fully_automated"
	} else if profile.BehaviorMetrics.RequestRate > 5.0 && profile.BehaviorMetrics.TimingConsistency > 0.7 {
		return "semi_automated"
	} else if profile.BehaviorMetrics.TimingConsistency < 0.3 {
		return "manual"
	} else {
		return "mixed"
	}
}

func (ap *AttackerProfiler) assessPersistenceLevel(profile *SessionProfile) string {
	score := profile.PersistenceScore
	
	if score > 0.8 {
		return "very_persistent"
	} else if score > 0.6 {
		return "persistent"
	} else if score > 0.4 {
		return "moderate"
	} else {
		return "low"
	}
}

func (ap *AttackerProfiler) assessThreatLevel(profile *SessionProfile) string {
	// Combine multiple factors
	threatScore := 0.0
	
	// Sophistication weight
	threatScore += profile.SophisticationScore * 0.4
	
	// Persistence weight
	threatScore += profile.PersistenceScore * 0.3
	
	// Attack diversity weight
	threatScore += math.Min(profile.BehaviorMetrics.AttackDiversity/3.0, 1.0) * 0.3
	
	if threatScore > 0.8 {
		return "critical"
	} else if threatScore > 0.6 {
		return "high"
	} else if threatScore > 0.4 {
		return "medium"
	} else {
		return "low"
	}
}

func (ap *AttackerProfiler) generateRecommendations(profile *SessionProfile) []string {
	var recommendations []string
	
	// Based on attacker type
	if profile.SophisticationScore > 0.7 {
		recommendations = append(recommendations, "Deploy advanced threat detection systems")
		recommendations = append(recommendations, "Implement behavioral analysis and anomaly detection")
	}
	
	if profile.PersistenceScore > 0.6 {
		recommendations = append(recommendations, "Implement IP-based rate limiting and blocking")
		recommendations = append(recommendations, "Monitor for repeated attack patterns")
	}
	
	if profile.BehaviorMetrics.AttackDiversity > 2.0 {
		recommendations = append(recommendations, "Strengthen input validation across all attack vectors")
		recommendations = append(recommendations, "Deploy comprehensive Web Application Firewall rules")
	}
	
	// Based on technical markers
	hasEvasion := false
	hasAdvanced := false
	for _, marker := range profile.TechnicalMarkers {
		if marker.Type == "evasion_method" {
			hasEvasion = true
		}
		if marker.Type == "advanced_technique" {
			hasAdvanced = true
		}
	}
	
	if hasEvasion {
		recommendations = append(recommendations, "Review and update WAF evasion detection rules")
	}
	
	if hasAdvanced {
		recommendations = append(recommendations, "Consider threat hunting and advanced forensic analysis")
	}
	
	return recommendations
}

// Helper methods

func (ap *AttackerProfiler) containsBase64Like(s string) bool {
	// Simple heuristic for base64-like strings
	if len(s) < 8 || len(s)%4 != 0 {
		return false
	}
	
	validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	validCount := 0
	for _, char := range s {
		for _, valid := range validChars {
			if char == valid {
				validCount++
				break
			}
		}
	}
	
	return float64(validCount)/float64(len(s)) > 0.8
}

func (ap *AttackerProfiler) hasCaseVariation(s string) bool {
	keywords := []string{"select", "union", "insert", "update", "delete", "script", "alert"}
	
	for _, keyword := range keywords {
		if strings.Contains(strings.ToLower(s), keyword) {
			// Check for mixed case
			if !strings.Contains(s, keyword) && !strings.Contains(s, strings.ToUpper(keyword)) {
				return true
			}
		}
	}
	
	return false
}

func (ap *AttackerProfiler) hasBlindInjectionPattern(s string) bool {
	patterns := []string{
		"and 1=1", "and 1=2", "or 1=1", "or 1=2",
		"and true", "and false", "and sleep", "waitfor delay",
	}
	
	lower := strings.ToLower(s)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	
	return false
}

func (ap *AttackerProfiler) hasPolyglotPattern(s string) bool {
	// Simplified polyglot detection
	hasSQL := strings.Contains(strings.ToLower(s), "union") || strings.Contains(strings.ToLower(s), "select")
	hasXSS := strings.Contains(s, "<script") || strings.Contains(s, "javascript:")
	hasCommand := strings.Contains(s, ";") || strings.Contains(s, "|")
	
	// If payload works across multiple contexts
	contextCount := 0
	if hasSQL {
		contextCount++
	}
	if hasXSS {
		contextCount++
	}
	if hasCommand {
		contextCount++
	}
	
	return contextCount >= 2
}

func (ap *AttackerProfiler) hasCustomFingerprinting(r *http.Request) bool {
	unusualHeaders := 0
	for name := range r.Header {
		if ap.isUnusualHeader(name) {
			unusualHeaders++
		}
	}
	
	return unusualHeaders > 3
}

// Additional helper methods for fingerprint generation

func (ap *AttackerProfiler) extractRequestPatterns(profile *SessionProfile) []string {
	patterns := make(map[string]bool)
	
	for _, req := range profile.RequestSequence {
		patterns[req.PathPattern] = true
	}
	
	var result []string
	for pattern := range patterns {
		result = append(result, pattern)
	}
	
	return result
}

func (ap *AttackerProfiler) extractHeaderPatterns(profile *SessionProfile) []string {
	patterns := make(map[string]bool)
	
	for _, req := range profile.RequestSequence {
		patterns[req.HeaderSignature] = true
	}
	
	var result []string
	for pattern := range patterns {
		result = append(result, pattern)
	}
	
	return result
}

func (ap *AttackerProfiler) extractAttackSequence(profile *SessionProfile) []string {
	var sequence []string
	
	for _, req := range profile.RequestSequence {
		if req.AttackType != "benign" {
			sequence = append(sequence, req.AttackType)
		}
	}
	
	return sequence
}

func (ap *AttackerProfiler) calculateTimingProfile(profile *SessionProfile) TimingProfile {
	if len(profile.RequestTimings) == 0 {
		return TimingProfile{}
	}
	
	// Calculate statistics
	sum := time.Duration(0)
	min := profile.RequestTimings[0]
	max := profile.RequestTimings[0]
	
	for _, timing := range profile.RequestTimings {
		sum += timing
		if timing < min {
			min = timing
		}
		if timing > max {
			max = timing
		}
	}
	
	avg := sum / time.Duration(len(profile.RequestTimings))
	
	// Calculate standard deviation
	varSum := 0.0
	for _, timing := range profile.RequestTimings {
		diff := timing - avg
		varSum += float64(diff * diff)
	}
	stdDev := time.Duration(math.Sqrt(varSum / float64(len(profile.RequestTimings))))
	
	return TimingProfile{
		AverageInterval: avg,
		StandardDev:     stdDev,
		MinInterval:     min,
		MaxInterval:     max,
		Consistency:     profile.BehaviorMetrics.TimingConsistency,
	}
}

func (ap *AttackerProfiler) generateFingerprintHash(requestPatterns, headerPatterns, attackSequence []string) string {
	combined := strings.Join(requestPatterns, "|") + ";" +
		strings.Join(headerPatterns, "|") + ";" +
		strings.Join(attackSequence, "|")
	
	hash := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", hash[:16])
}

func (ap *AttackerProfiler) addUniqueIP(ips []string, newIP string) []string {
	for _, ip := range ips {
		if ip == newIP {
			return ips
		}
	}
	return append(ips, newIP)
}

func (ap *AttackerProfiler) calculateUserAgentConsistency(profile *SessionProfile) float64 {
	if len(profile.UserAgents) <= 1 {
		return 1.0
	}
	
	// Simple consistency check - same UA used throughout
	firstUA := profile.UserAgents[0]
	consistent := 0
	for _, ua := range profile.UserAgents {
		if ua == firstUA {
			consistent++
		}
	}
	
	return float64(consistent) / float64(len(profile.UserAgents))
}

func (ap *AttackerProfiler) calculateAttackPatternConsistency(profile *SessionProfile) float64 {
	if len(profile.RequestSequence) < 2 {
		return 1.0
	}
	
	// Calculate consistency in attack patterns
	// This is a simplified version - could be more sophisticated
	attackTypes := make(map[string]int)
	for _, req := range profile.RequestSequence {
		if req.AttackType != "benign" {
			attackTypes[req.AttackType]++
		}
	}
	
	if len(attackTypes) == 0 {
		return 1.0
	}
	
	// Higher consistency if fewer different attack types
	return 1.0 / float64(len(attackTypes))
}