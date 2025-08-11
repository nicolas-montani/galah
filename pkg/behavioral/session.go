package behavioral

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SessionManager provides session management and persistence
type SessionManager struct {
	profiler    *AttackerProfiler
	dataDir     string
	cleanupTicker *time.Ticker
	stopChan    chan bool
	mutex       sync.RWMutex
}

// NewSessionManager creates a new session manager
func NewSessionManager(profiler *AttackerProfiler, dataDir string) *SessionManager {
	if dataDir == "" {
		dataDir = "behavioral_data"
	}
	
	// Ensure data directory exists
	os.MkdirAll(dataDir, 0755)
	
	sm := &SessionManager{
		profiler:   profiler,
		dataDir:    dataDir,
		stopChan:   make(chan bool),
	}
	
	// Start cleanup routine
	sm.startCleanupRoutine()
	
	return sm
}

// GetSessionProfile returns the current session profile
func (sm *SessionManager) GetSessionProfile(sessionID string) (*SessionProfile, bool) {
	sm.profiler.mutex.RLock()
	defer sm.profiler.mutex.RUnlock()
	
	profile, exists := sm.profiler.sessions[sessionID]
	return profile, exists
}

// GetAllSessions returns all active session profiles
func (sm *SessionManager) GetAllSessions() map[string]*SessionProfile {
	sm.profiler.mutex.RLock()
	defer sm.profiler.mutex.RUnlock()
	
	// Return a copy to avoid concurrent access issues
	sessions := make(map[string]*SessionProfile)
	for id, profile := range sm.profiler.sessions {
		sessions[id] = profile
	}
	
	return sessions
}

// GetBehavioralFingerprint returns a behavioral fingerprint by hash
func (sm *SessionManager) GetBehavioralFingerprint(hash string) (*BehavioralFingerprint, bool) {
	sm.profiler.mutex.RLock()
	defer sm.profiler.mutex.RUnlock()
	
	fingerprint, exists := sm.profiler.fingerprints[hash]
	return fingerprint, exists
}

// GetAllFingerprints returns all behavioral fingerprints
func (sm *SessionManager) GetAllFingerprints() map[string]*BehavioralFingerprint {
	sm.profiler.mutex.RLock()
	defer sm.profiler.mutex.RUnlock()
	
	// Return a copy
	fingerprints := make(map[string]*BehavioralFingerprint)
	for hash, fp := range sm.profiler.fingerprints {
		fingerprints[hash] = fp
	}
	
	return fingerprints
}

// GetAttackPatterns returns all known attack patterns
func (sm *SessionManager) GetAttackPatterns() map[string]*AttackPattern {
	sm.profiler.mutex.RLock()
	defer sm.profiler.mutex.RUnlock()
	
	// Return a copy
	patterns := make(map[string]*AttackPattern)
	for id, pattern := range sm.profiler.patterns {
		patterns[id] = pattern
	}
	
	return patterns
}

// ExportSessionData exports session data in various formats
func (sm *SessionManager) ExportSessionData(sessionID string, format string) error {
	profile, exists := sm.GetSessionProfile(sessionID)
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}
	
	switch format {
	case "json":
		return sm.exportSessionJSON(profile)
	case "csv":
		return sm.exportSessionCSV(profile)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// ExportAllData exports all behavioral data
func (sm *SessionManager) ExportAllData(format string) error {
	switch format {
	case "json":
		return sm.exportAllJSON()
	case "csv":
		return sm.exportAllCSV()
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// PersistSession saves session data to disk
func (sm *SessionManager) PersistSession(sessionID string) error {
	profile, exists := sm.GetSessionProfile(sessionID)
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}
	
	filename := filepath.Join(sm.dataDir, fmt.Sprintf("session_%s.json", sessionID))
	
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}
	
	return os.WriteFile(filename, data, 0644)
}

// LoadSession loads session data from disk
func (sm *SessionManager) LoadSession(sessionID string) error {
	filename := filepath.Join(sm.dataDir, fmt.Sprintf("session_%s.json", sessionID))
	
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read session file: %w", err)
	}
	
	var profile SessionProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return fmt.Errorf("failed to unmarshal session data: %w", err)
	}
	
	sm.profiler.mutex.Lock()
	sm.profiler.sessions[sessionID] = &profile
	sm.profiler.mutex.Unlock()
	
	return nil
}

// GenerateReport generates a comprehensive behavioral report
func (sm *SessionManager) GenerateReport(sessionID string) (*BehavioralReport, error) {
	profile, exists := sm.GetSessionProfile(sessionID)
	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}
	
	// Get the latest analysis
	analysis := sm.profiler.AnalyzeRequest(nil, sessionID, []string{}, 0)
	
	report := &BehavioralReport{
		SessionID:        sessionID,
		GeneratedAt:      time.Now(),
		SessionProfile:   *profile,
		Analysis:         *analysis,
		Summary:          sm.generateSummary(profile, analysis),
		RiskAssessment:   sm.assessRisk(profile, analysis),
		Recommendations:  analysis.Recommendations,
		RelatedSessions:  sm.findRelatedSessions(profile),
	}
	
	return report, nil
}

// BehavioralReport represents a comprehensive behavioral analysis report
type BehavioralReport struct {
	SessionID        string              `json:"session_id"`
	GeneratedAt      time.Time           `json:"generated_at"`
	SessionProfile   SessionProfile      `json:"session_profile"`
	Analysis         BehavioralAnalysis  `json:"analysis"`
	Summary          string              `json:"summary"`
	RiskAssessment   RiskAssessment      `json:"risk_assessment"`
	Recommendations  []string            `json:"recommendations"`
	RelatedSessions  []string            `json:"related_sessions"`
}

// RiskAssessment represents risk assessment for behavioral analysis
type RiskAssessment struct {
	OverallRisk      float64 `json:"overall_risk"`      // 0-10 scale
	ImmediateThreat  bool    `json:"immediate_threat"`
	RequiresResponse bool    `json:"requires_response"`
	PriorityLevel    string  `json:"priority_level"`    // "low", "medium", "high", "critical"
}

// GetStatistics returns behavioral analysis statistics
func (sm *SessionManager) GetStatistics() *BehavioralStatistics {
	sm.profiler.mutex.RLock()
	defer sm.profiler.mutex.RUnlock()
	
	stats := &BehavioralStatistics{
		TotalSessions:     len(sm.profiler.sessions),
		TotalFingerprints: len(sm.profiler.fingerprints),
		AttackerTypes:     make(map[string]int),
		SkillLevels:       make(map[string]int),
		ThreatLevels:      make(map[string]int),
		AttackPatterns:    make(map[string]int),
	}
	
	// Analyze all sessions for statistics
	for sessionID := range sm.profiler.sessions {
		// This would require running analysis on each session
		// Simplified for now
		_ = sessionID // Mark as used
		stats.AttackerTypes["unknown"]++
		stats.SkillLevels["unknown"]++
		stats.ThreatLevels["unknown"]++
	}
	
	return stats
}

// BehavioralStatistics represents system-wide behavioral statistics
type BehavioralStatistics struct {
	TotalSessions     int            `json:"total_sessions"`
	TotalFingerprints int            `json:"total_fingerprints"`
	AttackerTypes     map[string]int `json:"attacker_types"`
	SkillLevels       map[string]int `json:"skill_levels"`
	ThreatLevels      map[string]int `json:"threat_levels"`
	AttackPatterns    map[string]int `json:"attack_patterns"`
	LastUpdated       time.Time      `json:"last_updated"`
}

// CleanupOldSessions removes old sessions and data
func (sm *SessionManager) CleanupOldSessions(maxAge time.Duration) {
	sm.profiler.mutex.Lock()
	defer sm.profiler.mutex.Unlock()
	
	cutoff := time.Now().Add(-maxAge)
	
	// Clean up sessions
	for sessionID, profile := range sm.profiler.sessions {
		if profile.LastActivity.Before(cutoff) {
			delete(sm.profiler.sessions, sessionID)
		}
	}
	
	// Clean up fingerprints
	for hash, fingerprint := range sm.profiler.fingerprints {
		if fingerprint.LastSeen.Before(cutoff) {
			delete(sm.profiler.fingerprints, hash)
		}
	}
}

// Private methods

func (sm *SessionManager) startCleanupRoutine() {
	sm.cleanupTicker = time.NewTicker(1 * time.Hour)
	
	go func() {
		for {
			select {
			case <-sm.cleanupTicker.C:
				sm.CleanupOldSessions(24 * time.Hour) // Clean up sessions older than 24 hours
			case <-sm.stopChan:
				sm.cleanupTicker.Stop()
				return
			}
		}
	}()
}

func (sm *SessionManager) generateSummary(profile *SessionProfile, analysis *BehavioralAnalysis) string {
	summary := fmt.Sprintf("Session %s analyzed with %d requests over %v. ",
		profile.SessionID,
		len(profile.RequestSequence),
		profile.LastActivity.Sub(profile.StartTime))
	
	summary += fmt.Sprintf("Classified as %s with %s skill level. ",
		analysis.AttackerType,
		analysis.SkillLevel)
	
	summary += fmt.Sprintf("Threat level: %s. ", analysis.ThreatLevel)
	
	if len(analysis.AttackPatterns) > 0 {
		summary += fmt.Sprintf("Detected %d attack patterns. ", len(analysis.AttackPatterns))
	}
	
	if analysis.BehavioralFingerprint.SeenCount > 1 {
		summary += fmt.Sprintf("Behavioral fingerprint seen %d times previously. ",
			analysis.BehavioralFingerprint.SeenCount)
	}
	
	return summary
}

func (sm *SessionManager) assessRisk(profile *SessionProfile, analysis *BehavioralAnalysis) RiskAssessment {
	// Calculate overall risk
	riskScore := 0.0
	
	// Base risk from sophistication
	riskScore += analysis.BehavioralFingerprint.Characteristics["sophistication"] * 3.0
	
	// Risk from persistence
	if analysis.PersistenceLevel == "very_persistent" {
		riskScore += 3.0
	} else if analysis.PersistenceLevel == "persistent" {
		riskScore += 2.0
	}
	
	// Risk from threat level
	switch analysis.ThreatLevel {
	case "critical":
		riskScore += 4.0
	case "high":
		riskScore += 3.0
	case "medium":
		riskScore += 2.0
	case "low":
		riskScore += 1.0
	}
	
	// Cap at 10
	if riskScore > 10.0 {
		riskScore = 10.0
	}
	
	// Determine immediate threat
	immediateThreat := riskScore > 7.0 || analysis.ThreatLevel == "critical"
	
	// Determine response requirement
	requiresResponse := riskScore > 5.0
	
	// Determine priority
	priority := "low"
	if riskScore > 8.0 {
		priority = "critical"
	} else if riskScore > 6.0 {
		priority = "high"
	} else if riskScore > 4.0 {
		priority = "medium"
	}
	
	return RiskAssessment{
		OverallRisk:      riskScore,
		ImmediateThreat:  immediateThreat,
		RequiresResponse: requiresResponse,
		PriorityLevel:    priority,
	}
}

func (sm *SessionManager) findRelatedSessions(profile *SessionProfile) []string {
	var related []string
	
	sm.profiler.mutex.RLock()
	defer sm.profiler.mutex.RUnlock()
	
	// Find sessions with same fingerprint
	for sessionID, otherProfile := range sm.profiler.sessions {
		if sessionID != profile.SessionID &&
		   otherProfile.FingerprintHash == profile.FingerprintHash {
			related = append(related, sessionID)
		}
	}
	
	// Find sessions from same IP
	for sessionID, otherProfile := range sm.profiler.sessions {
		if sessionID != profile.SessionID &&
		   otherProfile.SourceIP == profile.SourceIP &&
		   otherProfile.FingerprintHash != profile.FingerprintHash {
			related = append(related, sessionID)
		}
	}
	
	return related
}

// Export methods

func (sm *SessionManager) exportSessionJSON(profile *SessionProfile) error {
	filename := filepath.Join(sm.dataDir, fmt.Sprintf("export_session_%s_%d.json",
		profile.SessionID, time.Now().Unix()))
	
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(filename, data, 0644)
}

func (sm *SessionManager) exportSessionCSV(profile *SessionProfile) error {
	filename := filepath.Join(sm.dataDir, fmt.Sprintf("export_session_%s_%d.csv",
		profile.SessionID, time.Now().Unix()))
	
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Write CSV header
	header := "timestamp,method,path_pattern,attack_type,confidence,response_time_ms\n"
	if _, err := file.WriteString(header); err != nil {
		return err
	}
	
	// Write request data
	for _, req := range profile.RequestSequence {
		line := fmt.Sprintf("%s,%s,%s,%s,%.2f,%.0f\n",
			req.Timestamp.Format(time.RFC3339),
			req.Method,
			req.PathPattern,
			req.AttackType,
			req.Confidence,
			float64(req.ResponseTime.Nanoseconds())/1000000.0,
		)
		if _, err := file.WriteString(line); err != nil {
			return err
		}
	}
	
	return nil
}

func (sm *SessionManager) exportAllJSON() error {
	allData := struct {
		Sessions     map[string]*SessionProfile      `json:"sessions"`
		Fingerprints map[string]*BehavioralFingerprint `json:"fingerprints"`
		Patterns     map[string]*AttackPattern       `json:"patterns"`
		ExportedAt   time.Time                       `json:"exported_at"`
	}{
		Sessions:     sm.GetAllSessions(),
		Fingerprints: sm.GetAllFingerprints(),
		Patterns:     sm.GetAttackPatterns(),
		ExportedAt:   time.Now(),
	}
	
	filename := filepath.Join(sm.dataDir, fmt.Sprintf("behavioral_export_%d.json", time.Now().Unix()))
	
	data, err := json.MarshalIndent(allData, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(filename, data, 0644)
}

func (sm *SessionManager) exportAllCSV() error {
	filename := filepath.Join(sm.dataDir, fmt.Sprintf("behavioral_export_%d.csv", time.Now().Unix()))
	
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Write comprehensive CSV with all session data
	header := "session_id,source_ip,start_time,last_activity,request_count,attack_diversity,timing_consistency,sophistication_score,persistence_score,fingerprint_hash\n"
	if _, err := file.WriteString(header); err != nil {
		return err
	}
	
	sessions := sm.GetAllSessions()
	for _, profile := range sessions {
		line := fmt.Sprintf("%s,%s,%s,%s,%d,%.2f,%.2f,%.2f,%.2f,%s\n",
			profile.SessionID,
			profile.SourceIP,
			profile.StartTime.Format(time.RFC3339),
			profile.LastActivity.Format(time.RFC3339),
			len(profile.RequestSequence),
			profile.BehaviorMetrics.AttackDiversity,
			profile.BehaviorMetrics.TimingConsistency,
			profile.SophisticationScore,
			profile.PersistenceScore,
			profile.FingerprintHash,
		)
		if _, err := file.WriteString(line); err != nil {
			return err
		}
	}
	
	return nil
}

// Stop stops the session manager
func (sm *SessionManager) Stop() {
	if sm.cleanupTicker != nil {
		sm.stopChan <- true
	}
}