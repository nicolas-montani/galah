package behavioral

import (
	"crypto/sha256"
	"fmt"
	"math"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// AttackerProfiler provides advanced behavioral analysis and attacker profiling
type AttackerProfiler struct {
	sessions     map[string]*SessionProfile
	fingerprints map[string]*BehavioralFingerprint
	patterns     map[string]*AttackPattern
	mutex        sync.RWMutex
}

// SessionProfile contains comprehensive behavioral data for an attack session
type SessionProfile struct {
	SessionID        string
	StartTime        time.Time
	LastActivity     time.Time
	SourceIP         string
	UserAgents       []string
	RequestTimings   []time.Duration
	RequestSequence  []RequestSignature
	AttackVectors    map[string]int
	TechnicalMarkers []TechnicalMarker
	BehaviorMetrics  BehaviorMetrics
	ProfileUpdated   time.Time
	
	// Advanced profiling
	ConsistencyScore  float64
	SophisticationScore float64
	PersistenceScore   float64
	FingerprintHash    string
}

// RequestSignature represents the signature of an HTTP request
type RequestSignature struct {
	Timestamp       time.Time
	Method          string
	PathPattern     string
	HeaderSignature string
	PayloadType     string
	AttackType      string
	Confidence      float64
	ResponseTime    time.Duration
}

// TechnicalMarker represents technical indicators of attacker skill/tools
type TechnicalMarker struct {
	Type        string    // "tool_signature", "encoding_technique", "evasion_method"
	Description string
	Confidence  float64
	Evidence    string
	Timestamp   time.Time
}

// BehaviorMetrics contains quantified behavioral characteristics
type BehaviorMetrics struct {
	RequestRate          float64   // Requests per minute
	SessionDuration      time.Duration
	AttackDiversity      float64   // Shannon entropy of attack types
	TimingConsistency    float64   // Consistency of request timing
	ErrorRate            float64   // Rate of failed requests
	ProgressionComplexity float64  // Complexity of attack progression
	AdaptationRate       float64   // Rate of strategy changes
	PersistenceIndicator float64   // Likelihood of returning
}

// BehavioralFingerprint represents a unique behavioral pattern
type BehavioralFingerprint struct {
	Hash             string
	RequestPatterns  []string
	TimingProfile    TimingProfile
	HeaderPatterns   []string
	AttackSequence   []string
	Characteristics  map[string]float64
	FirstSeen        time.Time
	LastSeen         time.Time
	SeenCount        int
	AssociatedIPs    []string
}

// TimingProfile represents timing characteristics
type TimingProfile struct {
	AverageInterval  time.Duration
	StandardDev      time.Duration
	MinInterval      time.Duration
	MaxInterval      time.Duration
	Consistency      float64  // 0-1, higher means more consistent timing
}

// AttackPattern represents a recognized attack pattern
type AttackPattern struct {
	ID              string
	Name            string
	Description     string
	Characteristics []string
	RequiredMarkers []string
	Confidence      float64
	Examples        []string
}

// NewAttackerProfiler creates a new behavioral profiler
func NewAttackerProfiler() *AttackerProfiler {
	profiler := &AttackerProfiler{
		sessions:     make(map[string]*SessionProfile),
		fingerprints: make(map[string]*BehavioralFingerprint),
		patterns:     make(map[string]*AttackPattern),
	}
	
	// Initialize known attack patterns
	profiler.initializeAttackPatterns()
	
	return profiler
}

// AnalyzeRequest performs behavioral analysis on an HTTP request
func (ap *AttackerProfiler) AnalyzeRequest(r *http.Request, sessionID string, attackVectors []string, responseTime time.Duration) *BehavioralAnalysis {
	ap.mutex.Lock()
	defer ap.mutex.Unlock()
	
	// Get or create session profile
	profile := ap.getOrCreateSession(sessionID, r)
	
	// Create request signature
	signature := ap.createRequestSignature(r, attackVectors, responseTime)
	profile.RequestSequence = append(profile.RequestSequence, signature)
	
	// Update behavioral metrics
	ap.updateBehaviorMetrics(profile, signature)
	
	// Detect technical markers
	markers := ap.detectTechnicalMarkers(r, signature)
	profile.TechnicalMarkers = append(profile.TechnicalMarkers, markers...)
	
	// Update profiling scores
	ap.updateProfilingScores(profile)
	
	// Generate behavioral fingerprint
	fingerprint := ap.generateFingerprint(profile)
	profile.FingerprintHash = fingerprint.Hash
	
	// Identify attack patterns
	patterns := ap.identifyAttackPatterns(profile)
	
	// Create analysis result
	analysis := &BehavioralAnalysis{
		SessionID:           sessionID,
		ProfileConfidence:   ap.calculateProfileConfidence(profile),
		AttackerType:        ap.classifyAttackerType(profile),
		SkillLevel:          ap.assessSkillLevel(profile),
		AutomationLevel:     ap.assessAutomationLevel(profile),
		PersistenceLevel:    ap.assessPersistenceLevel(profile),
		ThreatLevel:         ap.assessThreatLevel(profile),
		BehavioralFingerprint: fingerprint,
		AttackPatterns:      patterns,
		TechnicalMarkers:    markers,
		BehaviorMetrics:     profile.BehaviorMetrics,
		Recommendations:     ap.generateRecommendations(profile),
		Timestamp:          time.Now(),
	}
	
	return analysis
}

// BehavioralAnalysis represents the result of behavioral analysis
type BehavioralAnalysis struct {
	SessionID             string
	ProfileConfidence     float64
	AttackerType          string
	SkillLevel            string
	AutomationLevel       string
	PersistenceLevel      string
	ThreatLevel          string
	BehavioralFingerprint *BehavioralFingerprint
	AttackPatterns        []AttackPattern
	TechnicalMarkers      []TechnicalMarker
	BehaviorMetrics       BehaviorMetrics
	Recommendations       []string
	Timestamp            time.Time
}

// getOrCreateSession gets existing session or creates new one
func (ap *AttackerProfiler) getOrCreateSession(sessionID string, r *http.Request) *SessionProfile {
	if profile, exists := ap.sessions[sessionID]; exists {
		profile.LastActivity = time.Now()
		return profile
	}
	
	// Extract source IP
	sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	
	profile := &SessionProfile{
		SessionID:       sessionID,
		StartTime:       time.Now(),
		LastActivity:    time.Now(),
		SourceIP:        sourceIP,
		UserAgents:      []string{},
		RequestTimings:  []time.Duration{},
		RequestSequence: []RequestSignature{},
		AttackVectors:   make(map[string]int),
		TechnicalMarkers: []TechnicalMarker{},
		ProfileUpdated:  time.Now(),
	}
	
	ap.sessions[sessionID] = profile
	return profile
}

// createRequestSignature creates a signature for the HTTP request
func (ap *AttackerProfiler) createRequestSignature(r *http.Request, attackVectors []string, responseTime time.Duration) RequestSignature {
	// Generate path pattern (generalize dynamic parts)
	pathPattern := ap.generalizePath(r.URL.Path)
	
	// Generate header signature
	headerSig := ap.generateHeaderSignature(r.Header)
	
	// Determine primary attack type
	attackType := "benign"
	confidence := 0.0
	if len(attackVectors) > 0 {
		attackType = attackVectors[0]
		confidence = 0.8 // Base confidence
	}
	
	// Determine payload type
	payloadType := ap.classifyPayloadType(r)
	
	return RequestSignature{
		Timestamp:       time.Now(),
		Method:          r.Method,
		PathPattern:     pathPattern,
		HeaderSignature: headerSig,
		PayloadType:     payloadType,
		AttackType:      attackType,
		Confidence:      confidence,
		ResponseTime:    responseTime,
	}
}

// generalizePath generalizes URL paths to patterns
func (ap *AttackerProfiler) generalizePath(path string) string {
	// Replace numeric IDs with placeholders
	parts := strings.Split(path, "/")
	for i, part := range parts {
		// Replace numeric parts
		if len(part) > 0 && isNumeric(part) {
			parts[i] = "{id}"
		}
		// Replace long strings that might be IDs
		if len(part) > 20 {
			parts[i] = "{token}"
		}
	}
	return strings.Join(parts, "/")
}

// generateHeaderSignature creates a signature from HTTP headers
func (ap *AttackerProfiler) generateHeaderSignature(headers http.Header) string {
	// Create signature from header names and key values
	var elements []string
	
	// Standard headers that indicate client characteristics
	if ua := headers.Get("User-Agent"); ua != "" {
		elements = append(elements, "UA:"+ap.categorizeUserAgent(ua))
	}
	if accept := headers.Get("Accept"); accept != "" {
		elements = append(elements, "Accept:"+accept)
	}
	if encoding := headers.Get("Accept-Encoding"); encoding != "" {
		elements = append(elements, "Encoding:"+encoding)
	}
	if lang := headers.Get("Accept-Language"); lang != "" {
		elements = append(elements, "Lang:"+lang)
	}
	
	// Custom/unusual headers
	for name := range headers {
		if ap.isUnusualHeader(name) {
			elements = append(elements, "Custom:"+name)
		}
	}
	
	// Sort for consistency
	sort.Strings(elements)
	
	// Create hash
	combined := strings.Join(elements, "|")
	hash := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", hash[:8])
}

// categorizeUserAgent categorizes user agent strings
func (ap *AttackerProfiler) categorizeUserAgent(ua string) string {
	ua = strings.ToLower(ua)
	
	// Security tools
	tools := []string{"nikto", "sqlmap", "nmap", "burp", "dirb", "gobuster", 
		           "wpscan", "nuclei", "ffuf", "dirsearch", "masscan"}
	for _, tool := range tools {
		if strings.Contains(ua, tool) {
			return "security_tool"
		}
	}
	
	// Programming languages/libraries
	langs := []string{"python", "curl", "wget", "java", "go", "ruby", "perl"}
	for _, lang := range langs {
		if strings.Contains(ua, lang) {
			return "script"
		}
	}
	
	// Browsers
	if strings.Contains(ua, "mozilla") || strings.Contains(ua, "chrome") || 
	   strings.Contains(ua, "firefox") || strings.Contains(ua, "safari") {
		return "browser"
	}
	
	// Bots/crawlers
	if strings.Contains(ua, "bot") || strings.Contains(ua, "crawl") ||
	   strings.Contains(ua, "spider") {
		return "bot"
	}
	
	return "unknown"
}

// isUnusualHeader checks if a header is unusual/custom
func (ap *AttackerProfiler) isUnusualHeader(name string) bool {
	standardHeaders := map[string]bool{
		"Host": true, "User-Agent": true, "Accept": true, "Accept-Language": true,
		"Accept-Encoding": true, "Connection": true, "Upgrade-Insecure-Requests": true,
		"Sec-Fetch-Dest": true, "Sec-Fetch-Mode": true, "Sec-Fetch-Site": true,
		"Cache-Control": true, "Content-Type": true, "Content-Length": true,
		"Authorization": true, "Cookie": true, "Referer": true,
	}
	
	return !standardHeaders[name]
}

// classifyPayloadType classifies the request payload type
func (ap *AttackerProfiler) classifyPayloadType(r *http.Request) string {
	contentType := r.Header.Get("Content-Type")
	
	if strings.Contains(contentType, "application/json") {
		return "json"
	}
	if strings.Contains(contentType, "application/xml") || strings.Contains(contentType, "text/xml") {
		return "xml"
	}
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		return "form"
	}
	if strings.Contains(contentType, "multipart/form-data") {
		return "multipart"
	}
	if r.ContentLength > 0 {
		return "text"
	}
	
	return "none"
}

// updateBehaviorMetrics updates behavioral metrics for the session
func (ap *AttackerProfiler) updateBehaviorMetrics(profile *SessionProfile, signature RequestSignature) {
	// Update attack vector counts
	if signature.AttackType != "benign" {
		profile.AttackVectors[signature.AttackType]++
	}
	
	// Update timing data
	if len(profile.RequestSequence) > 1 {
		interval := signature.Timestamp.Sub(profile.RequestSequence[len(profile.RequestSequence)-2].Timestamp)
		profile.RequestTimings = append(profile.RequestTimings, interval)
	}
	
	// Calculate metrics
	profile.BehaviorMetrics = ap.calculateBehaviorMetrics(profile)
}

// calculateBehaviorMetrics calculates comprehensive behavioral metrics
func (ap *AttackerProfiler) calculateBehaviorMetrics(profile *SessionProfile) BehaviorMetrics {
	metrics := BehaviorMetrics{}
	
	// Request rate
	if len(profile.RequestSequence) > 1 {
		duration := profile.LastActivity.Sub(profile.StartTime)
		metrics.RequestRate = float64(len(profile.RequestSequence)) / duration.Minutes()
	}
	
	// Session duration
	metrics.SessionDuration = profile.LastActivity.Sub(profile.StartTime)
	
	// Attack diversity (Shannon entropy)
	metrics.AttackDiversity = ap.calculateAttackDiversity(profile.AttackVectors)
	
	// Timing consistency
	metrics.TimingConsistency = ap.calculateTimingConsistency(profile.RequestTimings)
	
	// Error rate (would need response codes - placeholder)
	metrics.ErrorRate = 0.0
	
	// Progression complexity
	metrics.ProgressionComplexity = ap.calculateProgressionComplexity(profile.RequestSequence)
	
	// Adaptation rate
	metrics.AdaptationRate = ap.calculateAdaptationRate(profile.RequestSequence)
	
	// Persistence indicator
	metrics.PersistenceIndicator = ap.calculatePersistenceIndicator(profile)
	
	return metrics
}

// calculateAttackDiversity calculates Shannon entropy of attack types
func (ap *AttackerProfiler) calculateAttackDiversity(attackVectors map[string]int) float64 {
	if len(attackVectors) == 0 {
		return 0.0
	}
	
	total := 0
	for _, count := range attackVectors {
		total += count
	}
	
	if total == 0 {
		return 0.0
	}
	
	entropy := 0.0
	for _, count := range attackVectors {
		if count > 0 {
			p := float64(count) / float64(total)
			entropy -= p * math.Log2(p)
		}
	}
	
	return entropy
}

// calculateTimingConsistency calculates consistency of request timing
func (ap *AttackerProfiler) calculateTimingConsistency(timings []time.Duration) float64 {
	if len(timings) < 2 {
		return 1.0
	}
	
	// Calculate mean and standard deviation
	sum := time.Duration(0)
	for _, timing := range timings {
		sum += timing
	}
	mean := sum / time.Duration(len(timings))
	
	varSum := 0.0
	for _, timing := range timings {
		diff := timing - mean
		varSum += float64(diff * diff)
	}
	
	variance := varSum / float64(len(timings))
	stdDev := math.Sqrt(variance)
	
	// Normalize by mean to get coefficient of variation
	cv := stdDev / float64(mean)
	
	// Return inverse CV as consistency (0-1, higher is more consistent)
	consistency := 1.0 / (1.0 + cv)
	return consistency
}

// calculateProgressionComplexity calculates complexity of attack progression
func (ap *AttackerProfiler) calculateProgressionComplexity(sequence []RequestSignature) float64 {
	if len(sequence) < 3 {
		return 0.0
	}
	
	// Count unique attack types in sequence
	attackTypes := make(map[string]bool)
	for _, req := range sequence {
		if req.AttackType != "benign" {
			attackTypes[req.AttackType] = true
		}
	}
	
	// Complexity based on variety and sequence length
	variety := float64(len(attackTypes))
	length := float64(len(sequence))
	
	// Normalize to 0-1 scale
	complexity := (variety * math.Log(length)) / 10.0
	if complexity > 1.0 {
		complexity = 1.0
	}
	
	return complexity
}

// calculateAdaptationRate calculates rate of strategy changes
func (ap *AttackerProfiler) calculateAdaptationRate(sequence []RequestSignature) float64 {
	if len(sequence) < 3 {
		return 0.0
	}
	
	changes := 0
	for i := 1; i < len(sequence); i++ {
		if sequence[i].AttackType != sequence[i-1].AttackType {
			changes++
		}
	}
	
	return float64(changes) / float64(len(sequence)-1)
}

// calculatePersistenceIndicator calculates likelihood of persistence
func (ap *AttackerProfiler) calculatePersistenceIndicator(profile *SessionProfile) float64 {
	// Based on session duration and request count
	duration := profile.LastActivity.Sub(profile.StartTime)
	requestCount := len(profile.RequestSequence)
	
	// Longer sessions with more requests indicate higher persistence
	durationScore := math.Min(duration.Hours()/24.0, 1.0) // Normalize to 24 hours
	requestScore := math.Min(float64(requestCount)/100.0, 1.0) // Normalize to 100 requests
	
	return (durationScore + requestScore) / 2.0
}

// Helper function to check if string is numeric
func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}