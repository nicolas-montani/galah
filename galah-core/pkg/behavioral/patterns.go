package behavioral

import (
	"strings"
)

// initializeAttackPatterns initializes known attack patterns
func (ap *AttackerProfiler) initializeAttackPatterns() {
	patterns := []*AttackPattern{
		{
			ID:          "automated_scanner",
			Name:        "Automated Vulnerability Scanner",
			Description: "Systematic scanning using automated tools",
			Characteristics: []string{
				"high_request_rate", "consistent_timing", "tool_signature",
				"directory_enumeration", "parameter_fuzzing",
			},
			RequiredMarkers: []string{"tool_signature"},
			Confidence:      0.8,
			Examples: []string{
				"Nikto scanner with systematic directory traversal",
				"SQLMap with automated injection testing",
			},
		},
		{
			ID:          "manual_exploration",
			Name:        "Manual Security Testing", 
			Description: "Human-driven security exploration",
			Characteristics: []string{
				"variable_timing", "browser_signature", "logical_progression",
				"response_analysis", "adaptive_behavior",
			},
			RequiredMarkers: []string{"browser_signature"},
			Confidence:      0.7,
			Examples: []string{
				"Manual browsing with occasional injection attempts",
				"Human-driven penetration testing workflow",
			},
		},
		{
			ID:          "targeted_exploitation",
			Name:        "Targeted Exploitation Campaign",
			Description: "Focused attack on specific vulnerabilities",
			Characteristics: []string{
				"specific_payloads", "persistence", "evasion_techniques",
				"advanced_techniques", "low_noise",
			},
			RequiredMarkers: []string{"advanced_technique", "evasion_method"},
			Confidence:      0.9,
			Examples: []string{
				"Custom exploit development and testing",
				"APT-style focused exploitation",
			},
		},
		{
			ID:          "opportunistic_scanning",
			Name:        "Opportunistic Vulnerability Scanning",
			Description: "Broad scanning for common vulnerabilities",
			Characteristics: []string{
				"broad_coverage", "common_payloads", "high_volume",
				"minimal_evasion", "automated_patterns",
			},
			RequiredMarkers: []string{"tool_signature"},
			Confidence:      0.6,
			Examples: []string{
				"Mass scanning campaigns",
				"Bot-driven exploitation attempts",
			},
		},
		{
			ID:          "reconnaissance_mission",
			Name:        "Information Gathering Campaign",
			Description: "Systematic information collection",
			Characteristics: []string{
				"info_gathering", "low_impact", "stealth_approach",
				"broad_enumeration", "minimal_exploitation",
			},
			RequiredMarkers: []string{},
			Confidence:      0.5,
			Examples: []string{
				"Directory enumeration and fingerprinting",
				"Technology stack identification",
			},
		},
		{
			ID:          "script_kiddie_activity",
			Name:        "Script Kiddie Attack",
			Description: "Unsophisticated automated attacks",
			Characteristics: []string{
				"basic_payloads", "no_evasion", "tool_signature",
				"low_sophistication", "common_patterns",
			},
			RequiredMarkers: []string{"tool_signature"},
			Confidence:      0.7,
			Examples: []string{
				"Copy-paste exploit attempts",
				"Basic tool usage without customization",
			},
		},
		{
			ID:          "advanced_persistent_threat",
			Name:        "Advanced Persistent Threat",
			Description: "Sophisticated, long-term attack campaign",
			Characteristics: []string{
				"multi_stage", "advanced_techniques", "persistence",
				"evasion_techniques", "custom_tools", "low_profile",
			},
			RequiredMarkers: []string{"advanced_technique", "evasion_method"},
			Confidence:      0.95,
			Examples: []string{
				"Nation-state sponsored attacks",
				"Advanced organized cybercrime",
			},
		},
		{
			ID:          "web_application_fuzzing",
			Name:        "Web Application Fuzzing",
			Description: "Systematic input validation testing",
			Characteristics: []string{
				"parameter_fuzzing", "boundary_testing", "error_analysis",
				"systematic_approach", "payload_variations",
			},
			RequiredMarkers: []string{},
			Confidence:      0.6,
			Examples: []string{
				"Burp Suite Intruder fuzzing",
				"Custom fuzzing scripts",
			},
		},
		{
			ID:          "injection_specialist",
			Name:        "Injection Attack Specialist",
			Description: "Focused on injection vulnerabilities",
			Characteristics: []string{
				"injection_focus", "payload_expertise", "encoding_techniques",
				"blind_techniques", "advanced_payloads",
			},
			RequiredMarkers: []string{"advanced_technique"},
			Confidence:      0.8,
			Examples: []string{
				"Expert SQL injection campaigns",
				"Advanced XSS payload development",
			},
		},
		{
			ID:          "bot_network_probe",
			Name:        "Botnet Reconnaissance",
			Description: "Distributed scanning from botnet",
			Characteristics: []string{
				"distributed_sources", "consistent_patterns", "high_volume",
				"minimal_sophistication", "repeated_attempts",
			},
			RequiredMarkers: []string{},
			Confidence:      0.6,
			Examples: []string{
				"Coordinated botnet scanning",
				"Mass exploitation attempts",
			},
		},
	}
	
	// Store patterns
	for _, pattern := range patterns {
		ap.patterns[pattern.ID] = pattern
	}
}

// identifyAttackPatterns identifies matching attack patterns for a session
func (ap *AttackerProfiler) identifyAttackPatterns(profile *SessionProfile) []AttackPattern {
	var matchedPatterns []AttackPattern
	
	for _, pattern := range ap.patterns {
		if ap.matchesPattern(profile, pattern) {
			matchedPatterns = append(matchedPatterns, *pattern)
		}
	}
	
	return matchedPatterns
}

// matchesPattern checks if a session profile matches an attack pattern
func (ap *AttackerProfiler) matchesPattern(profile *SessionProfile, pattern *AttackPattern) bool {
	// Check required markers first
	requiredMarkersMet := 0
	for _, requiredMarker := range pattern.RequiredMarkers {
		for _, marker := range profile.TechnicalMarkers {
			if ap.markerMatches(marker, requiredMarker) {
				requiredMarkersMet++
				break
			}
		}
	}
	
	// If required markers not met, pattern doesn't match
	if requiredMarkersMet < len(pattern.RequiredMarkers) {
		return false
	}
	
	// Score characteristics
	characteristicScore := 0.0
	characteristicsChecked := 0
	
	for _, characteristic := range pattern.Characteristics {
		characteristicsChecked++
		if ap.hasCharacteristic(profile, characteristic) {
			characteristicScore += 1.0
		}
	}
	
	// Calculate match score
	if characteristicsChecked == 0 {
		return requiredMarkersMet == len(pattern.RequiredMarkers)
	}
	
	matchScore := characteristicScore / float64(characteristicsChecked)
	
	// Pattern matches if score is above threshold
	return matchScore >= 0.6
}

// markerMatches checks if a technical marker matches a required pattern marker
func (ap *AttackerProfiler) markerMatches(marker TechnicalMarker, required string) bool {
	switch required {
	case "tool_signature":
		return marker.Type == "tool_signature"
	case "advanced_technique":
		return marker.Type == "advanced_technique"
	case "evasion_method":
		return marker.Type == "evasion_method"
	case "encoding_technique":
		return marker.Type == "encoding_technique"
	case "browser_signature":
		return marker.Type == "tool_signature" && 
			   (marker.Description == "browser" || marker.Description == "Professional web security testing")
	default:
		return false
	}
}

// hasCharacteristic checks if a session profile has a specific characteristic
func (ap *AttackerProfiler) hasCharacteristic(profile *SessionProfile, characteristic string) bool {
	switch characteristic {
	case "high_request_rate":
		return profile.BehaviorMetrics.RequestRate > 5.0
	
	case "consistent_timing":
		return profile.BehaviorMetrics.TimingConsistency > 0.8
	
	case "variable_timing":
		return profile.BehaviorMetrics.TimingConsistency < 0.5
	
	case "tool_signature":
		for _, marker := range profile.TechnicalMarkers {
			if marker.Type == "tool_signature" {
				return true
			}
		}
		return false
	
	case "browser_signature":
		// Check if any user agent indicates browser usage
		return ap.hasBrowserSignature(profile)
	
	case "directory_enumeration":
		return ap.hasDirectoryEnumeration(profile)
	
	case "parameter_fuzzing":
		return ap.hasParameterFuzzing(profile)
	
	case "logical_progression":
		return ap.hasLogicalProgression(profile)
	
	case "response_analysis":
		return ap.hasResponseAnalysis(profile)
	
	case "adaptive_behavior":
		return profile.BehaviorMetrics.AdaptationRate > 0.3
	
	case "specific_payloads":
		return ap.hasSpecificPayloads(profile)
	
	case "persistence":
		return profile.PersistenceScore > 0.6
	
	case "evasion_techniques":
		for _, marker := range profile.TechnicalMarkers {
			if marker.Type == "evasion_method" {
				return true
			}
		}
		return false
	
	case "advanced_techniques":
		for _, marker := range profile.TechnicalMarkers {
			if marker.Type == "advanced_technique" {
				return true
			}
		}
		return false
	
	case "low_noise":
		return profile.BehaviorMetrics.RequestRate < 2.0
	
	case "broad_coverage":
		return profile.BehaviorMetrics.AttackDiversity > 2.0
	
	case "common_payloads":
		return ap.hasCommonPayloads(profile)
	
	case "high_volume":
		return len(profile.RequestSequence) > 50
	
	case "minimal_evasion":
		evasionCount := 0
		for _, marker := range profile.TechnicalMarkers {
			if marker.Type == "evasion_method" {
				evasionCount++
			}
		}
		return evasionCount <= 1
	
	case "automated_patterns":
		return profile.BehaviorMetrics.TimingConsistency > 0.7 && 
			   profile.BehaviorMetrics.RequestRate > 3.0
	
	case "info_gathering":
		return ap.hasInfoGathering(profile)
	
	case "low_impact":
		return ap.hasLowImpact(profile)
	
	case "stealth_approach":
		return profile.BehaviorMetrics.RequestRate < 1.0
	
	case "broad_enumeration":
		return ap.hasBroadEnumeration(profile)
	
	case "minimal_exploitation":
		exploitCount := 0
		for _, vector := range profile.AttackVectors {
			exploitCount += vector
		}
		return exploitCount < 5
	
	case "basic_payloads":
		return ap.hasBasicPayloads(profile)
	
	case "no_evasion":
		for _, marker := range profile.TechnicalMarkers {
			if marker.Type == "evasion_method" {
				return false
			}
		}
		return true
	
	case "low_sophistication":
		return profile.SophisticationScore < 0.3
	
	case "common_patterns":
		return ap.hasCommonPatterns(profile)
	
	case "multi_stage":
		return ap.hasMultiStage(profile)
	
	case "custom_tools":
		return ap.hasCustomTools(profile)
	
	case "low_profile":
		return profile.BehaviorMetrics.RequestRate < 0.5
	
	case "boundary_testing":
		return ap.hasBoundaryTesting(profile)
	
	case "error_analysis":
		return ap.hasErrorAnalysis(profile)
	
	case "systematic_approach":
		return profile.BehaviorMetrics.ProgressionComplexity > 0.5
	
	case "payload_variations":
		return ap.hasPayloadVariations(profile)
	
	case "injection_focus":
		injectionCount := 0
		for attackType := range profile.AttackVectors {
			if ap.isInjectionAttack(attackType) {
				injectionCount++
			}
		}
		return injectionCount >= 2
	
	case "payload_expertise":
		return profile.SophisticationScore > 0.7
	
	case "encoding_techniques":
		for _, marker := range profile.TechnicalMarkers {
			if marker.Type == "encoding_technique" {
				return true
			}
		}
		return false
	
	case "blind_techniques":
		return ap.hasBlindTechniques(profile)
	
	case "advanced_payloads":
		return ap.hasAdvancedPayloads(profile)
	
	case "distributed_sources":
		// This would require tracking across multiple sessions - simplified
		return false
	
	case "repeated_attempts":
		return len(profile.RequestSequence) > 20
	
	default:
		return false
	}
}

// Helper methods for characteristic detection

func (ap *AttackerProfiler) hasBrowserSignature(profile *SessionProfile) bool {
	// Check if any request sequence indicates browser usage
	for _, req := range profile.RequestSequence {
		// This would need access to original request data
		// Simplified implementation
		if req.PayloadType == "form" || req.PayloadType == "multipart" {
			return true
		}
	}
	return false
}

func (ap *AttackerProfiler) hasDirectoryEnumeration(profile *SessionProfile) bool {
	directoryPaths := 0
	for _, req := range profile.RequestSequence {
		if strings.Contains(req.PathPattern, "/admin") ||
		   strings.Contains(req.PathPattern, "/backup") ||
		   strings.Contains(req.PathPattern, "/config") {
			directoryPaths++
		}
	}
	return directoryPaths > 3
}

func (ap *AttackerProfiler) hasParameterFuzzing(profile *SessionProfile) bool {
	// Check for systematic parameter testing
	parameterVariations := make(map[string]int)
	for _, req := range profile.RequestSequence {
		parameterVariations[req.PathPattern]++
	}
	
	// If same path with many variations, likely parameter fuzzing
	for _, count := range parameterVariations {
		if count > 10 {
			return true
		}
	}
	return false
}

func (ap *AttackerProfiler) hasLogicalProgression(profile *SessionProfile) bool {
	// Check for logical attack progression
	if len(profile.RequestSequence) < 3 {
		return false
	}
	
	// Simple heuristic: check if reconnaissance followed by exploitation
	hasRecon := false
	hasExploit := false
	
	for i, req := range profile.RequestSequence {
		if i < len(profile.RequestSequence)/2 && req.AttackType == "reconnaissance" {
			hasRecon = true
		}
		if i > len(profile.RequestSequence)/2 && ap.isExploitAttack(req.AttackType) {
			hasExploit = true
		}
	}
	
	return hasRecon && hasExploit
}

func (ap *AttackerProfiler) hasResponseAnalysis(profile *SessionProfile) bool {
	// Check for patterns indicating response analysis
	// This would require access to response data - simplified
	return profile.BehaviorMetrics.AdaptationRate > 0.2
}

func (ap *AttackerProfiler) hasSpecificPayloads(profile *SessionProfile) bool {
	// Check for custom/specific payloads vs common ones
	return profile.SophisticationScore > 0.6
}

func (ap *AttackerProfiler) hasCommonPayloads(profile *SessionProfile) bool {
	// Check for usage of common, basic payloads
	return profile.SophisticationScore < 0.4
}

func (ap *AttackerProfiler) hasInfoGathering(profile *SessionProfile) bool {
	// Check for information gathering patterns
	infoGathering := 0
	for _, req := range profile.RequestSequence {
		if req.Method == "OPTIONS" || req.Method == "HEAD" ||
		   strings.Contains(req.PathPattern, "/robots.txt") ||
		   strings.Contains(req.PathPattern, "/.well-known") {
			infoGathering++
		}
	}
	return infoGathering > 2
}

func (ap *AttackerProfiler) hasLowImpact(profile *SessionProfile) bool {
	// Check for low-impact reconnaissance activities
	highImpactAttacks := 0
	for attackType := range profile.AttackVectors {
		if ap.isHighImpactAttack(attackType) {
			highImpactAttacks++
		}
	}
	return highImpactAttacks < 2
}

func (ap *AttackerProfiler) hasBroadEnumeration(profile *SessionProfile) bool {
	// Check for broad enumeration patterns
	uniquePaths := make(map[string]bool)
	for _, req := range profile.RequestSequence {
		uniquePaths[req.PathPattern] = true
	}
	return len(uniquePaths) > 10
}

func (ap *AttackerProfiler) hasBasicPayloads(profile *SessionProfile) bool {
	return profile.SophisticationScore < 0.3
}

func (ap *AttackerProfiler) hasCommonPatterns(profile *SessionProfile) bool {
	// Check for usage of common attack patterns
	commonAttacks := 0
	for attackType := range profile.AttackVectors {
		if ap.isCommonAttack(attackType) {
			commonAttacks++
		}
	}
	return commonAttacks > 0
}

func (ap *AttackerProfiler) hasMultiStage(profile *SessionProfile) bool {
	// Check for multi-stage attack patterns
	stages := make(map[string]bool)
	for _, req := range profile.RequestSequence {
		if req.AttackType != "benign" {
			stages[req.AttackType] = true
		}
	}
	return len(stages) > 3
}

func (ap *AttackerProfiler) hasCustomTools(profile *SessionProfile) bool {
	// Check for custom tool signatures
	for _, marker := range profile.TechnicalMarkers {
		if marker.Type == "tool_signature" && marker.Confidence < 0.7 {
			return true // Lower confidence might indicate custom tools
		}
	}
	return false
}

func (ap *AttackerProfiler) hasBoundaryTesting(profile *SessionProfile) bool {
	// Check for boundary value testing patterns
	return ap.hasParameterFuzzing(profile)
}

func (ap *AttackerProfiler) hasErrorAnalysis(profile *SessionProfile) bool {
	// Check for error-based analysis patterns
	return profile.BehaviorMetrics.AdaptationRate > 0.3
}

func (ap *AttackerProfiler) hasPayloadVariations(profile *SessionProfile) bool {
	// Check for systematic payload variations
	return profile.BehaviorMetrics.AttackDiversity > 1.5
}

func (ap *AttackerProfiler) hasBlindTechniques(profile *SessionProfile) bool {
	// Check for blind injection techniques
	for _, marker := range profile.TechnicalMarkers {
		if marker.Type == "advanced_technique" && 
		   strings.Contains(marker.Description, "blind") {
			return true
		}
	}
	return false
}

func (ap *AttackerProfiler) hasAdvancedPayloads(profile *SessionProfile) bool {
	return profile.SophisticationScore > 0.8
}

// Classification helpers

func (ap *AttackerProfiler) isInjectionAttack(attackType string) bool {
	injectionTypes := []string{
		"sql_injection", "xss", "command_injection", 
		"ldap_injection", "xpath_injection", "nosql_injection",
	}
	
	for _, injType := range injectionTypes {
		if attackType == injType {
			return true
		}
	}
	return false
}

func (ap *AttackerProfiler) isExploitAttack(attackType string) bool {
	exploitTypes := []string{
		"sql_injection", "xss", "command_injection", "file_inclusion",
		"xxe", "ssrf", "deserialization",
	}
	
	for _, explType := range exploitTypes {
		if attackType == explType {
			return true
		}
	}
	return false
}

func (ap *AttackerProfiler) isHighImpactAttack(attackType string) bool {
	highImpactTypes := []string{
		"command_injection", "file_inclusion", "ssrf", 
		"deserialization", "xxe",
	}
	
	for _, hiType := range highImpactTypes {
		if attackType == hiType {
			return true
		}
	}
	return false
}

func (ap *AttackerProfiler) isCommonAttack(attackType string) bool {
	commonTypes := []string{
		"sql_injection", "xss", "directory_traversal",
	}
	
	for _, commonType := range commonTypes {
		if attackType == commonType {
			return true
		}
	}
	return false
}