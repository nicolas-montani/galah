package mitre

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Classifier provides MITRE ATT&CK technique classification for HTTP requests
type Classifier struct {
	techniques         map[string]AttackTechnique
	httpMappings       map[string]HTTPAttackMapping
	tacticMappings     map[string]TacticMapping
	compiledPatterns   map[string]*regexp.Regexp
	dataFile          string
}

// NewClassifier creates a new MITRE ATT&CK classifier
func NewClassifier(dataFile string) (*Classifier, error) {
	if dataFile == "" {
		dataFile = "data/mitre/techniques.json"
	}
	
	classifier := &Classifier{
		techniques:       make(map[string]AttackTechnique),
		httpMappings:     make(map[string]HTTPAttackMapping),
		tacticMappings:   make(map[string]TacticMapping),
		compiledPatterns: make(map[string]*regexp.Regexp),
		dataFile:        dataFile,
	}
	
	if err := classifier.LoadTechniques(); err != nil {
		return nil, fmt.Errorf("failed to load techniques: %w", err)
	}
	
	return classifier, nil
}

// TechniqueData represents the JSON structure for technique data
type TechniqueData struct {
	Techniques       []AttackTechnique     `json:"techniques"`
	Tactics          []TacticMapping       `json:"tactics"`
	HTTPMappings     []HTTPAttackMapping   `json:"http_attack_mappings"`
}

// LoadTechniques loads MITRE ATT&CK techniques from JSON data file
func (c *Classifier) LoadTechniques() error {
	// Try to read from the data file
	var data []byte
	var err error
	
	if c.dataFile != "" {
		data, err = ioutil.ReadFile(c.dataFile)
		if err != nil {
			// If file doesn't exist, fall back to embedded data
			data = []byte(getEmbeddedTechniqueData())
		}
	} else {
		data = []byte(getEmbeddedTechniqueData())
	}
	
	var techniqueData TechniqueData
	if err := json.Unmarshal(data, &techniqueData); err != nil {
		return fmt.Errorf("failed to parse technique data: %w", err)
	}
	
	// Load techniques
	for _, technique := range techniqueData.Techniques {
		c.techniques[technique.ID] = technique
		
		// Pre-compile regex patterns for performance
		for i, pattern := range technique.Patterns {
			if pattern.IsRegex {
				key := fmt.Sprintf("%s_pattern_%d", technique.ID, i)
				compiled, err := regexp.Compile(pattern.Pattern)
				if err != nil {
					return fmt.Errorf("invalid regex pattern for technique %s: %w", technique.ID, err)
				}
				c.compiledPatterns[key] = compiled
			}
		}
		
		// Compile sub-technique patterns
		for _, subTech := range technique.SubTechniques {
			for i, pattern := range subTech.Patterns {
				if pattern.IsRegex {
					key := fmt.Sprintf("%s_pattern_%d", subTech.ID, i)
					compiled, err := regexp.Compile(pattern.Pattern)
					if err != nil {
						return fmt.Errorf("invalid regex pattern for sub-technique %s: %w", subTech.ID, err)
					}
					c.compiledPatterns[key] = compiled
				}
			}
		}
	}
	
	// Load tactic mappings
	for _, tactic := range techniqueData.Tactics {
		c.tacticMappings[tactic.Tactic] = tactic
	}
	
	// Load HTTP attack mappings
	for _, mapping := range techniqueData.HTTPMappings {
		c.httpMappings[mapping.AttackType] = mapping
	}
	
	return nil
}

// ClassifyRequest analyzes an HTTP request and maps it to MITRE ATT&CK techniques
func (c *Classifier) ClassifyRequest(r *http.Request, body string, attackVectors []string) *ClassificationResult {
	result := &ClassificationResult{
		Matches:     []TechniqueMatch{},
		OverallRisk: 0.0,
		Confidence:  0.0,
	}
	
	// Start with attack vector-based classification
	for _, attackType := range attackVectors {
		if mapping, exists := c.httpMappings[attackType]; exists {
			for _, techniqueID := range mapping.Techniques {
				if technique, exists := c.techniques[techniqueID]; exists {
					match := c.evaluateTechnique(technique, r, body)
					if match != nil {
						match.Confidence = match.Confidence * mapping.Confidence
						result.Matches = append(result.Matches, *match)
					}
				}
			}
		}
	}
	
	// Pattern-based classification for all techniques
	for _, technique := range c.techniques {
		match := c.evaluateTechnique(technique, r, body)
		if match != nil {
			// Check if we already have this technique from attack vector mapping
			exists := false
			for i, existing := range result.Matches {
				if existing.Technique.ID == match.Technique.ID {
					// Update with higher confidence
					if match.Confidence > existing.Confidence {
						result.Matches[i] = *match
					}
					exists = true
					break
				}
			}
			if !exists {
				result.Matches = append(result.Matches, *match)
			}
		}
	}
	
	// Calculate overall metrics
	result.OverallRisk = c.calculateOverallRisk(result.Matches)
	result.Confidence = c.calculateOverallConfidence(result.Matches)
	result.PrimaryTactic = c.determinePrimaryTactic(result.Matches)
	result.AttackStage = c.determineAttackStage(result.Matches)
	result.Recommendations = c.generateRecommendations(result.Matches)
	
	return result
}

// evaluateTechnique evaluates a single technique against the HTTP request
func (c *Classifier) evaluateTechnique(technique AttackTechnique, r *http.Request, body string) *TechniqueMatch {
	evidence := []Evidence{}
	totalWeight := 0.0
	matchedWeight := 0.0
	
	// Evaluate main technique patterns
	for i, pattern := range technique.Patterns {
		weight := pattern.Weight
		totalWeight += weight
		
		if c.evaluatePattern(pattern, r, body, fmt.Sprintf("%s_pattern_%d", technique.ID, i)) {
			evidence = append(evidence, Evidence{
				Type:    "pattern_match",
				Source:  pattern.Type,
				Value:   c.extractMatchedValue(pattern, r, body),
				Pattern: pattern.Pattern,
				Weight:  weight,
			})
			matchedWeight += weight
		}
	}
	
	// Evaluate keyword matches
	for _, keyword := range technique.Keywords {
		weight := 0.3 // Lower weight for keyword matches
		totalWeight += weight
		
		if c.containsKeyword(keyword, r, body) {
			evidence = append(evidence, Evidence{
				Type:   "keyword_match",
				Source: "content",
				Value:  keyword,
				Weight: weight,
			})
			matchedWeight += weight
		}
	}
	
	// Evaluate sub-techniques
	var bestSubTechnique *SubTechnique
	bestSubConfidence := 0.0
	
	for _, subTech := range technique.SubTechniques {
		subEvidence := []Evidence{}
		subTotalWeight := 0.0
		subMatchedWeight := 0.0
		
		// Evaluate sub-technique patterns
		for i, pattern := range subTech.Patterns {
			weight := pattern.Weight
			subTotalWeight += weight
			
			if c.evaluatePattern(pattern, r, body, fmt.Sprintf("%s_pattern_%d", subTech.ID, i)) {
				subEvidence = append(subEvidence, Evidence{
					Type:    "pattern_match",
					Source:  pattern.Type,
					Value:   c.extractMatchedValue(pattern, r, body),
					Pattern: pattern.Pattern,
					Weight:  weight,
				})
				subMatchedWeight += weight
			}
		}
		
		// Evaluate sub-technique keywords
		for _, keyword := range subTech.Keywords {
			weight := 0.3
			subTotalWeight += weight
			
			if c.containsKeyword(keyword, r, body) {
				subEvidence = append(subEvidence, Evidence{
					Type:   "keyword_match",
					Source: "content", 
					Value:  keyword,
					Weight: weight,
				})
				subMatchedWeight += weight
			}
		}
		
		if subTotalWeight > 0 {
			subConfidence := subMatchedWeight / subTotalWeight
			if subConfidence > bestSubConfidence {
				bestSubConfidence = subConfidence
				bestSubTechnique = &subTech
				evidence = append(evidence, subEvidence...)
				totalWeight += subTotalWeight
				matchedWeight += subMatchedWeight
			}
		}
	}
	
	// Calculate confidence
	if totalWeight == 0 {
		return nil
	}
	
	confidence := matchedWeight / totalWeight
	
	// Minimum confidence threshold
	if confidence < 0.05 { // Lowered threshold for testing
		return nil
	}
	
	match := &TechniqueMatch{
		Technique:    technique,
		SubTechnique: bestSubTechnique,
		Confidence:   confidence,
		Evidence:     evidence,
		Timestamp:    time.Now(),
	}
	
	return match
}

// evaluatePattern evaluates a pattern against the HTTP request
func (c *Classifier) evaluatePattern(pattern PatternMatcher, r *http.Request, body, patternKey string) bool {
	var content string
	
	switch pattern.Type {
	case "url":
		content = r.URL.String()
	case "body":
		content = body
	case "method":
		content = r.Method
	case "user_agent":
		content = r.Header.Get("User-Agent")
	case "header":
		// Check all headers
		for name, values := range r.Header {
			content += name + ": " + strings.Join(values, ", ") + " "
		}
	default:
		return false
	}
	
	if !pattern.CaseSensitive {
		content = strings.ToLower(content)
	}
	
	if pattern.IsRegex {
		if compiled, exists := c.compiledPatterns[patternKey]; exists {
			return compiled.MatchString(content)
		}
		// Fallback to runtime compilation (less efficient)
		matched, _ := regexp.MatchString(pattern.Pattern, content)
		return matched
	} else {
		return strings.Contains(content, pattern.Pattern)
	}
}

// extractMatchedValue extracts the matched value for evidence
func (c *Classifier) extractMatchedValue(pattern PatternMatcher, r *http.Request, body string) string {
	var content string
	
	switch pattern.Type {
	case "url":
		content = r.URL.String()
	case "body":
		content = body
	case "method":
		content = r.Method
	case "user_agent":
		content = r.Header.Get("User-Agent")
	case "header":
		for name, values := range r.Header {
			content += name + ": " + strings.Join(values, ", ") + " "
		}
	}
	
	if pattern.IsRegex {
		re, _ := regexp.Compile(pattern.Pattern)
		matches := re.FindStringSubmatch(content)
		if len(matches) > 0 {
			return matches[0]
		}
	}
	
	// For non-regex or if regex fails, return truncated content
	if len(content) > 100 {
		return content[:100] + "..."
	}
	return content
}

// containsKeyword checks if content contains a keyword
func (c *Classifier) containsKeyword(keyword string, r *http.Request, body string) bool {
	allContent := strings.ToLower(r.URL.String() + " " + body + " " + r.Header.Get("User-Agent"))
	return strings.Contains(allContent, strings.ToLower(keyword))
}

// calculateOverallRisk calculates the overall risk score from matches
func (c *Classifier) calculateOverallRisk(matches []TechniqueMatch) float64 {
	if len(matches) == 0 {
		return 0.0
	}
	
	maxRisk := 0.0
	for _, match := range matches {
		// Risk calculation based on tactic and confidence
		tacticRisk := c.getTacticRiskScore(match.Technique.Tactic)
		risk := tacticRisk * match.Confidence
		if risk > maxRisk {
			maxRisk = risk
		}
	}
	
	// Bonus for multiple techniques
	if len(matches) > 1 {
		maxRisk += float64(len(matches)-1) * 0.5
	}
	
	// Cap at 10.0
	if maxRisk > 10.0 {
		maxRisk = 10.0
	}
	
	return maxRisk
}

// getTacticRiskScore returns base risk score for a tactic
func (c *Classifier) getTacticRiskScore(tactic string) float64 {
	tacticRisks := map[string]float64{
		"Initial Access":   9.0,
		"Execution":        8.5,
		"Persistence":      8.0,
		"Defense Evasion":  7.5,
		"Discovery":        6.0,
		"Reconnaissance":   4.0,
	}
	
	if risk, exists := tacticRisks[tactic]; exists {
		return risk
	}
	return 5.0 // Default
}

// calculateOverallConfidence calculates overall confidence from matches
func (c *Classifier) calculateOverallConfidence(matches []TechniqueMatch) float64 {
	if len(matches) == 0 {
		return 0.0
	}
	
	totalConfidence := 0.0
	for _, match := range matches {
		totalConfidence += match.Confidence
	}
	
	// Average confidence, capped at 1.0
	avgConfidence := totalConfidence / float64(len(matches))
	if avgConfidence > 1.0 {
		avgConfidence = 1.0
	}
	
	return avgConfidence
}

// determinePrimaryTactic determines the primary tactic from matches
func (c *Classifier) determinePrimaryTactic(matches []TechniqueMatch) string {
	if len(matches) == 0 {
		return ""
	}
	
	tacticCounts := make(map[string]float64)
	for _, match := range matches {
		tacticCounts[match.Technique.Tactic] += match.Confidence
	}
	
	maxCount := 0.0
	primaryTactic := ""
	for tactic, count := range tacticCounts {
		if count > maxCount {
			maxCount = count
			primaryTactic = tactic
		}
	}
	
	return primaryTactic
}

// determineAttackStage determines the attack stage based on tactics
func (c *Classifier) determineAttackStage(matches []TechniqueMatch) string {
	if len(matches) == 0 {
		return "unknown"
	}
	
	// Priority order for attack stages
	stageOrder := []string{
		"Reconnaissance",
		"Initial Access", 
		"Execution",
		"Persistence",
		"Discovery",
		"Defense Evasion",
	}
	
	tacticFound := make(map[string]bool)
	for _, match := range matches {
		tacticFound[match.Technique.Tactic] = true
	}
	
	// Return the earliest stage found
	for _, stage := range stageOrder {
		if tacticFound[stage] {
			return strings.ToLower(strings.ReplaceAll(stage, " ", "_"))
		}
	}
	
	return "unknown"
}

// generateRecommendations generates security recommendations based on matches
func (c *Classifier) generateRecommendations(matches []TechniqueMatch) []string {
	if len(matches) == 0 {
		return []string{}
	}
	
	recommendations := []string{}
	seen := make(map[string]bool)
	
	for _, match := range matches {
		switch match.Technique.Tactic {
		case "Initial Access":
			if !seen["input_validation"] {
				recommendations = append(recommendations, "Implement comprehensive input validation and sanitization")
				seen["input_validation"] = true
			}
			if !seen["waf"] {
				recommendations = append(recommendations, "Deploy Web Application Firewall (WAF) with updated rules")
				seen["waf"] = true
			}
		case "Reconnaissance":
			if !seen["rate_limiting"] {
				recommendations = append(recommendations, "Implement rate limiting and request throttling")
				seen["rate_limiting"] = true
			}
			if !seen["monitoring"] {
				recommendations = append(recommendations, "Enhanced monitoring for scanning activities")
				seen["monitoring"] = true
			}
		case "Execution":
			if !seen["code_exec_prevention"] {
				recommendations = append(recommendations, "Disable dangerous functions and implement code execution prevention")
				seen["code_exec_prevention"] = true
			}
		case "Persistence":
			if !seen["file_monitoring"] {
				recommendations = append(recommendations, "Monitor file uploads and web server modifications")
				seen["file_monitoring"] = true
			}
		}
	}
	
	return recommendations
}

// GetTechnique returns a technique by ID
func (c *Classifier) GetTechnique(id string) (AttackTechnique, bool) {
	technique, exists := c.techniques[id]
	return technique, exists
}

// GetAllTechniques returns all loaded techniques
func (c *Classifier) GetAllTechniques() map[string]AttackTechnique {
	return c.techniques
}

// GetHTTPMapping returns HTTP attack mapping for an attack type
func (c *Classifier) GetHTTPMapping(attackType string) (HTTPAttackMapping, bool) {
	mapping, exists := c.httpMappings[attackType]
	return mapping, exists
}

// getEmbeddedTechniqueData returns embedded JSON data as fallback
func getEmbeddedTechniqueData() string {
	// Embedded minimal technique data for testing and fallback
	return `{
		"techniques": [
			{
				"id": "T1190",
				"name": "Exploit Public-Facing Application",
				"tactic": "Initial Access",
				"description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program",
				"platforms": ["Linux", "Windows", "macOS", "Network"],
				"keywords": ["exploit", "vulnerability", "injection"],
				"patterns": [
					{
						"type": "body",
						"pattern": "(?i)(union|select|insert|update|delete|script)",
						"is_regex": true,
						"case_sensitive": false,
						"weight": 0.8
					},
					{
						"type": "url",
						"pattern": "(?i)(\\.\\./|%2e%2e%2f)",
						"is_regex": true,
						"case_sensitive": false,
						"weight": 0.9
					}
				],
				"sub_techniques": [
					{
						"id": "T1190.001",
						"name": "SQL Injection",
						"description": "SQL injection vulnerabilities",
						"keywords": ["sql", "injection", "union", "select"],
						"patterns": [
							{
								"type": "body",
								"pattern": "(?i)(union.*select|or.*1.*=.*1)",
								"is_regex": true,
								"case_sensitive": false,
								"weight": 0.95
							}
						]
					}
				]
			},
			{
				"id": "T1595",
				"name": "Active Scanning",
				"tactic": "Reconnaissance",
				"description": "Adversaries may execute active reconnaissance scans",
				"platforms": ["PRE"],
				"keywords": ["scanning", "probe", "reconnaissance"],
				"patterns": [
					{
						"type": "user_agent",
						"pattern": "(?i)(nikto|scanner|crawl)",
						"is_regex": true,
						"case_sensitive": false,
						"weight": 0.8
					}
				]
			}
		],
		"tactics": [
			{
				"tactic": "Reconnaissance",
				"description": "The adversary is trying to gather information"
			},
			{
				"tactic": "Initial Access",
				"description": "The adversary is trying to get into your network"
			}
		],
		"http_attack_mappings": [
			{
				"attack_type": "sql_injection",
				"primary_tactic": "Initial Access",
				"techniques": ["T1190", "T1190.001"],
				"confidence": 0.9
			},
			{
				"attack_type": "xss",
				"primary_tactic": "Initial Access",
				"techniques": ["T1190"],
				"confidence": 0.85
			}
		]
	}`
}