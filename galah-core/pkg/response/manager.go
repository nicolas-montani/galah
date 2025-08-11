package response

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ResponseManager coordinates all context-aware response generation components
type ResponseManager struct {
	contextAnalyzer  *ContextAnalyzer
	strategyEngine   *ResponseStrategyEngine
	contentGenerator *ContentGenerator
	
	// Configuration
	enabled          bool
	learningEnabled  bool
	adaptiveMode     bool
	responseTimeout  time.Duration
	
	// Metrics and monitoring
	responseMetrics  ResponseMetrics
	sessionCache     map[string]*CachedSession
	mutex           sync.RWMutex
	
	// Integration hooks
	eventLogger      func(event ResponseEvent)
	metricsCollector func(metrics ResponseMetrics)
}

// ResponseMetrics tracks response generation metrics
type ResponseMetrics struct {
	TotalResponses       int64                      `json:"total_responses"`
	ResponsesByType      map[string]int64           `json:"responses_by_type"`
	ResponsesByStrategy  map[string]int64           `json:"responses_by_strategy"`
	AvgResponseTime      float64                    `json:"avg_response_time_ms"`
	AvgComplexity        float64                    `json:"avg_complexity"`
	AvgAdaptiveness      float64                    `json:"avg_adaptiveness"`
	StrategyEffectiveness map[string]float64        `json:"strategy_effectiveness"`
	ContextDistribution  map[string]int64           `json:"context_distribution"`
	LearningEvents       int64                      `json:"learning_events"`
	AdaptiveAdjustments  int64                      `json:"adaptive_adjustments"`
	LastUpdated          time.Time                  `json:"last_updated"`
}

// CachedSession stores session-specific response context
type CachedSession struct {
	SessionID       string                     `json:"session_id"`
	FirstSeen       time.Time                  `json:"first_seen"`
	LastActivity    time.Time                  `json:"last_activity"`
	RequestCount    int                        `json:"request_count"`
	Context         *AttackContext             `json:"context"`
	ResponseHistory []ContextualResponse       `json:"response_history"`
	Effectiveness   []float64                  `json:"effectiveness"`
	Strategy        *ResponseStrategy          `json:"strategy"`
	Adaptations     int                        `json:"adaptations"`
}

// ResponseEvent represents a response generation event for logging
type ResponseEvent struct {
	Timestamp        time.Time              `json:"timestamp"`
	SessionID        string                 `json:"session_id"`
	RequestID        string                 `json:"request_id"`
	Context          AttackContext          `json:"context"`
	Strategy         ResponseStrategy       `json:"strategy"`
	Response         ContextualResponse     `json:"response"`
	GenerationTime   time.Duration          `json:"generation_time"`
	Effectiveness    float64                `json:"effectiveness"`
	EventType        string                 `json:"event_type"`
}

// NewResponseManager creates a new response manager
func NewResponseManager() *ResponseManager {
	contextAnalyzer := NewContextAnalyzer()
	strategyEngine := NewResponseStrategyEngine(contextAnalyzer)
	contentGenerator := NewContentGenerator()
	
	return &ResponseManager{
		contextAnalyzer:  contextAnalyzer,
		strategyEngine:   strategyEngine,
		contentGenerator: contentGenerator,
		enabled:          true,
		learningEnabled:  true,
		adaptiveMode:     true,
		responseTimeout:  5 * time.Second,
		responseMetrics:  ResponseMetrics{
			ResponsesByType:      make(map[string]int64),
			ResponsesByStrategy:  make(map[string]int64),
			StrategyEffectiveness: make(map[string]float64),
			ContextDistribution:  make(map[string]int64),
			LastUpdated:          time.Now(),
		},
		sessionCache:     make(map[string]*CachedSession),
	}
}

// GenerateContextAwareResponse generates a complete context-aware response
func (rm *ResponseManager) GenerateContextAwareResponse(r *http.Request, sessionID string, eventAnalysis *EventAnalysis) (*ContextualResponse, error) {
	if !rm.enabled {
		return rm.generateDefaultResponse(), nil
	}
	
	startTime := time.Now()
	
	// Analyze context
	context := rm.contextAnalyzer.AnalyzeContext(r, sessionID, eventAnalysis)
	
	// Update session cache
	rm.updateSessionCache(sessionID, context)
	
	// Select response strategy
	strategy := rm.strategyEngine.SelectStrategy(context)
	
	// Generate dynamic content
	generatedContent := rm.contentGenerator.GenerateResponse(context, strategy)
	
	// Create contextual response
	response := &ContextualResponse{
		ResponseType:     generatedContent.Type,
		Content:          generatedContent.Content,
		Headers:          generatedContent.Headers,
		StatusCode:       generatedContent.StatusCode,
		Complexity:       generatedContent.Complexity,
		Adaptiveness:     generatedContent.Adaptiveness,
		LearningValue:    rm.calculateLearningValue(context, strategy),
		ExpectedReaction: rm.predictAttackerReaction(context, strategy),
		Justification:    generatedContent.Justification,
	}
	
	// Record response for learning
	if rm.learningEnabled {
		rm.recordResponseForLearning(sessionID, context, strategy, response)
	}
	
	// Update metrics
	rm.updateMetrics(context, strategy, response, time.Since(startTime))
	
	// Log event
	if rm.eventLogger != nil {
		rm.eventLogger(ResponseEvent{
			Timestamp:      time.Now(),
			SessionID:      sessionID,
			RequestID:      rm.generateRequestID(r),
			Context:        *context,
			Strategy:       *strategy,
			Response:       *response,
			GenerationTime: time.Since(startTime),
			EventType:      "response_generated",
		})
	}
	
	return response, nil
}

// updateSessionCache updates the session cache with new context and response information
func (rm *ResponseManager) updateSessionCache(sessionID string, context *AttackContext) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	
	if session, exists := rm.sessionCache[sessionID]; exists {
		session.LastActivity = time.Now()
		session.RequestCount++
		session.Context = context
	} else {
		rm.sessionCache[sessionID] = &CachedSession{
			SessionID:       sessionID,
			FirstSeen:       time.Now(),
			LastActivity:    time.Now(),
			RequestCount:    1,
			Context:         context,
			ResponseHistory: []ContextualResponse{},
			Effectiveness:   []float64{},
			Adaptations:     0,
		}
	}
}

// recordResponseForLearning records response data for machine learning
func (rm *ResponseManager) recordResponseForLearning(sessionID string, context *AttackContext, strategy *ResponseStrategy, response *ContextualResponse) {
	// Record in strategy engine
	effectiveness := rm.estimateResponseEffectiveness(context, strategy, response)
	rm.strategyEngine.RecordStrategyResult(context, *strategy, *response, effectiveness)
	
	// Record in context analyzer
	requestID := fmt.Sprintf("%s_%d", sessionID, time.Now().Unix())
	rm.contextAnalyzer.RecordResponse(sessionID, requestID, response, effectiveness)
	
	// Update session cache
	rm.mutex.Lock()
	if session, exists := rm.sessionCache[sessionID]; exists {
		session.ResponseHistory = append(session.ResponseHistory, *response)
		session.Effectiveness = append(session.Effectiveness, effectiveness)
		session.Strategy = strategy
		
		// Trigger adaptation if needed
		if rm.adaptiveMode && rm.shouldAdapt(session) {
			session.Adaptations++
			rm.responseMetrics.AdaptiveAdjustments++
		}
	}
	rm.mutex.Unlock()
	
	rm.responseMetrics.LearningEvents++
}

// estimateResponseEffectiveness estimates how effective a response will be
func (rm *ResponseManager) estimateResponseEffectiveness(context *AttackContext, strategy *ResponseStrategy, response *ContextualResponse) float64 {
	effectiveness := 0.5 // Base effectiveness
	
	// Adjust based on context-strategy alignment
	if rm.isStrategyAligned(context, strategy) {
		effectiveness += 0.2
	}
	
	// Adjust based on response complexity vs attacker sophistication
	complexityAlignment := 1.0 - abs(response.Complexity-context.Sophistication)
	effectiveness += complexityAlignment * 0.2
	
	// Adjust based on adaptiveness
	effectiveness += response.Adaptiveness * 0.1
	
	// Adjust based on threat level
	switch context.ThreatLevel {
	case "critical":
		if response.Complexity > 0.7 {
			effectiveness += 0.1
		}
	case "low":
		if response.Complexity < 0.5 {
			effectiveness += 0.1
		}
	}
	
	// Ensure within bounds
	if effectiveness > 1.0 {
		effectiveness = 1.0
	}
	if effectiveness < 0.0 {
		effectiveness = 0.0
	}
	
	return effectiveness
}

// isStrategyAligned checks if the strategy is well-aligned with the context
func (rm *ResponseManager) isStrategyAligned(context *AttackContext, strategy *ResponseStrategy) bool {
	// Check if strategy conditions match context
	for _, condition := range strategy.Conditions {
		if rm.strategyEngine.evaluateCondition(condition, context) {
			return true
		}
	}
	return false
}

// shouldAdapt determines if the response strategy should be adapted
func (rm *ResponseManager) shouldAdapt(session *CachedSession) bool {
	if len(session.Effectiveness) < 3 {
		return false
	}
	
	// Calculate recent effectiveness trend
	recentEffectiveness := 0.0
	recentCount := minInt(len(session.Effectiveness), 3)
	
	for i := len(session.Effectiveness) - recentCount; i < len(session.Effectiveness); i++ {
		recentEffectiveness += session.Effectiveness[i]
	}
	recentEffectiveness /= float64(recentCount)
	
	// Adapt if effectiveness is declining
	return recentEffectiveness < 0.4
}

// predictAttackerReaction predicts how the attacker might react to the response
func (rm *ResponseManager) predictAttackerReaction(context *AttackContext, strategy *ResponseStrategy) string {
	if context.AttackerProfile == "professional_penetration_tester" {
		if strategy.Name == "Professional_Engagement" {
			return "continued_detailed_analysis"
		}
		return "adaptive_strategy_change"
	}
	
	if context.AttackerProfile == "automated_scanner" {
		if strategy.Name == "Scanner_Disruption" {
			return "scanner_confusion_or_timeout"
		}
		return "continued_automated_scanning"
	}
	
	if context.Evasion && strategy.Name == "Evasion_Counter" {
		return "escalated_evasion_techniques"
	}
	
	return "unknown"
}

// calculateLearningValue calculates the learning value of the response
func (rm *ResponseManager) calculateLearningValue(context *AttackContext, strategy *ResponseStrategy) float64 {
	learningValue := 0.5
	
	// Higher learning value for sophisticated attacks
	learningValue += context.Sophistication * 0.3
	
	// Higher learning value for adaptive strategies
	learningValue += strategy.Adaptiveness * 0.2
	
	// Higher learning value for novel contexts
	if rm.isNovelContext(context) {
		learningValue += 0.2
	}
	
	return min(learningValue, 1.0)
}

// isNovelContext determines if this is a novel attack context
func (rm *ResponseManager) isNovelContext(context *AttackContext) bool {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	
	// Check if we've seen similar contexts before
	for _, session := range rm.sessionCache {
		if session.Context != nil &&
			session.Context.AttackerProfile == context.AttackerProfile &&
			session.Context.ThreatLevel == context.ThreatLevel &&
			session.Context.AttackType == context.AttackType {
			return false
		}
	}
	
	return true
}

// updateMetrics updates response generation metrics
func (rm *ResponseManager) updateMetrics(context *AttackContext, strategy *ResponseStrategy, response *ContextualResponse, responseTime time.Duration) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	
	rm.responseMetrics.TotalResponses++
	rm.responseMetrics.ResponsesByType[response.ResponseType]++
	rm.responseMetrics.ResponsesByStrategy[strategy.Name]++
	
	// Update averages
	total := float64(rm.responseMetrics.TotalResponses)
	rm.responseMetrics.AvgResponseTime = (rm.responseMetrics.AvgResponseTime*(total-1) + float64(responseTime.Nanoseconds())/1e6) / total
	rm.responseMetrics.AvgComplexity = (rm.responseMetrics.AvgComplexity*(total-1) + response.Complexity) / total
	rm.responseMetrics.AvgAdaptiveness = (rm.responseMetrics.AvgAdaptiveness*(total-1) + response.Adaptiveness) / total
	
	// Update context distribution
	contextKey := fmt.Sprintf("%s_%s", context.AttackerProfile, context.ThreatLevel)
	rm.responseMetrics.ContextDistribution[contextKey]++
	
	// Update strategy effectiveness
	if effectiveness, exists := rm.responseMetrics.StrategyEffectiveness[strategy.Name]; exists {
		// Use exponential moving average
		alpha := 0.1
		estimated := rm.estimateResponseEffectiveness(context, strategy, response)
		rm.responseMetrics.StrategyEffectiveness[strategy.Name] = alpha*estimated + (1-alpha)*effectiveness
	} else {
		rm.responseMetrics.StrategyEffectiveness[strategy.Name] = rm.estimateResponseEffectiveness(context, strategy, response)
	}
	
	rm.responseMetrics.LastUpdated = time.Now()
	
	// Call metrics collector if set
	if rm.metricsCollector != nil {
		rm.metricsCollector(rm.responseMetrics)
	}
}

// generateDefaultResponse generates a basic default response
func (rm *ResponseManager) generateDefaultResponse() *ContextualResponse {
	return &ContextualResponse{
		ResponseType: "standard_response",
		Content: map[string]interface{}{
			"status":  "success",
			"message": "Request processed",
		},
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		StatusCode:       200,
		Complexity:       0.3,
		Adaptiveness:     0.2,
		LearningValue:    0.1,
		ExpectedReaction: "unknown",
		Justification:    "Default response - context analysis disabled",
	}
}

// generateRequestID generates a unique request ID
func (rm *ResponseManager) generateRequestID(r *http.Request) string {
	return fmt.Sprintf("%s_%d_%s", 
		r.RemoteAddr, 
		time.Now().UnixNano(), 
		r.URL.Path)
}

// Configuration methods

// SetEnabled enables or disables context-aware response generation
func (rm *ResponseManager) SetEnabled(enabled bool) {
	rm.enabled = enabled
}

// SetLearningEnabled enables or disables learning features
func (rm *ResponseManager) SetLearningEnabled(enabled bool) {
	rm.learningEnabled = enabled
	rm.strategyEngine.EnableAdaptiveLearning(enabled)
}

// SetAdaptiveMode enables or disables adaptive mode
func (rm *ResponseManager) SetAdaptiveMode(enabled bool) {
	rm.adaptiveMode = enabled
	rm.contentGenerator.SetAdaptiveMode(enabled)
}

// SetResponseTimeout sets the response generation timeout
func (rm *ResponseManager) SetResponseTimeout(timeout time.Duration) {
	rm.responseTimeout = timeout
}

// SetEventLogger sets the event logging function
func (rm *ResponseManager) SetEventLogger(logger func(ResponseEvent)) {
	rm.eventLogger = logger
}

// SetMetricsCollector sets the metrics collection function
func (rm *ResponseManager) SetMetricsCollector(collector func(ResponseMetrics)) {
	rm.metricsCollector = collector
}

// Data access methods

// GetResponseMetrics returns current response metrics
func (rm *ResponseManager) GetResponseMetrics() ResponseMetrics {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	return rm.responseMetrics
}

// GetSessionCache returns the current session cache
func (rm *ResponseManager) GetSessionCache() map[string]*CachedSession {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	
	// Return a copy to avoid race conditions
	cache := make(map[string]*CachedSession)
	for k, v := range rm.sessionCache {
		cache[k] = v
	}
	return cache
}

// GetStrategyEffectiveness returns strategy effectiveness data
func (rm *ResponseManager) GetStrategyEffectiveness() map[string]float64 {
	return rm.strategyEngine.GetStrategyEffectiveness()
}

// CleanupExpiredSessions removes expired sessions from cache
func (rm *ResponseManager) CleanupExpiredSessions(maxAge time.Duration) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	
	cutoff := time.Now().Add(-maxAge)
	for sessionID, session := range rm.sessionCache {
		if session.LastActivity.Before(cutoff) {
			delete(rm.sessionCache, sessionID)
		}
	}
}

// ExportResponseData exports all response data for research and analysis
func (rm *ResponseManager) ExportResponseData() ([]byte, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	
	contextData, _ := rm.contextAnalyzer.ExportContextData()
	exportData := map[string]interface{}{
		"metrics":       rm.responseMetrics,
		"session_cache": rm.sessionCache,
		"context_data":  string(contextData),
		"strategy_data": rm.strategyEngine.ExportStrategyData(),
		"generator_data": rm.contentGenerator.ExportGeneratorData(),
		"configuration": map[string]interface{}{
			"enabled":          rm.enabled,
			"learning_enabled": rm.learningEnabled,
			"adaptive_mode":    rm.adaptiveMode,
			"response_timeout": rm.responseTimeout,
		},
		"exported_at": time.Now(),
	}
	
	return json.MarshalIndent(exportData, "", "  ")
}

// Utility functions

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}