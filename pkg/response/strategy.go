package response

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"
)

// ResponseStrategy defines different response strategies for context-aware responses
type ResponseStrategy struct {
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Conditions     []StrategyCondition    `json:"conditions"`
	ResponseTypes  []string               `json:"response_types"`
	Adaptiveness   float64                `json:"adaptiveness"`
	LearningWeight float64                `json:"learning_weight"`
	Effectiveness  float64                `json:"effectiveness"`
	Parameters     map[string]interface{} `json:"parameters"`
}

// StrategyCondition defines when a strategy should be applied
type StrategyCondition struct {
	Field     string      `json:"field"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
	Weight    float64     `json:"weight"`
}

// ResponseStrategyEngine selects and executes response strategies
type ResponseStrategyEngine struct {
	strategies       []ResponseStrategy
	contextAnalyzer  *ContextAnalyzer
	adaptiveEnabled  bool
	learningRate     float64
	strategyHistory  map[string][]StrategyResult
	defaultStrategy  ResponseStrategy
}

// StrategyResult tracks the result of applying a strategy
type StrategyResult struct {
	Timestamp        time.Time         `json:"timestamp"`
	Strategy         ResponseStrategy  `json:"strategy"`
	Context          AttackContext     `json:"context"`
	Response         ContextualResponse `json:"response"`
	Effectiveness    float64           `json:"effectiveness"`
	AttackerReaction string            `json:"attacker_reaction"`
	SessionContinued bool              `json:"session_continued"`
	LearningValue    float64           `json:"learning_value"`
}

// NewResponseStrategyEngine creates a new response strategy engine
func NewResponseStrategyEngine(contextAnalyzer *ContextAnalyzer) *ResponseStrategyEngine {
	engine := &ResponseStrategyEngine{
		strategies:      []ResponseStrategy{},
		contextAnalyzer: contextAnalyzer,
		adaptiveEnabled: true,
		learningRate:    0.1,
		strategyHistory: make(map[string][]StrategyResult),
	}
	
	// Initialize default strategies
	engine.initializeDefaultStrategies()
	
	return engine
}

// initializeDefaultStrategies initializes the default response strategies
func (rse *ResponseStrategyEngine) initializeDefaultStrategies() {
	// High sophistication strategy - for advanced attackers
	rse.strategies = append(rse.strategies, ResponseStrategy{
		Name:        "Advanced_Engagement",
		Description: "Complex responses for sophisticated attackers",
		Conditions: []StrategyCondition{
			{Field: "sophistication", Operator: ">=", Value: 0.7, Weight: 0.8},
			{Field: "threat_level", Operator: "in", Value: []string{"high", "critical"}, Weight: 0.9},
		},
		ResponseTypes:  []string{"complex_honeypot", "advanced_deception", "intelligent_misdirection"},
		Adaptiveness:   0.9,
		LearningWeight: 0.8,
		Effectiveness:  0.75,
		Parameters: map[string]interface{}{
			"complexity_level":    0.9,
			"deception_layers":    3,
			"response_delay":      "variable",
			"content_randomness":  0.7,
		},
	})
	
	// Automated scanner strategy
	rse.strategies = append(rse.strategies, ResponseStrategy{
		Name:        "Scanner_Disruption",
		Description: "Responses designed to disrupt automated scanners",
		Conditions: []StrategyCondition{
			{Field: "attacker_profile", Operator: "in", Value: []string{"automated_scanner", "script_kiddie"}, Weight: 0.8},
			{Field: "automation_level", Operator: "==", Value: "automated", Weight: 0.7},
		},
		ResponseTypes:  []string{"rate_limit_simulation", "infinite_content", "scanner_confusion"},
		Adaptiveness:   0.6,
		LearningWeight: 0.5,
		Effectiveness:  0.8,
		Parameters: map[string]interface{}{
			"delay_tactics":       true,
			"content_size":        "large",
			"false_positives":     5,
			"redirect_loops":      true,
		},
	})
	
	// Evasion technique strategy
	rse.strategies = append(rse.strategies, ResponseStrategy{
		Name:        "Evasion_Counter",
		Description: "Counter-responses for evasion techniques",
		Conditions: []StrategyCondition{
			{Field: "evasion", Operator: "==", Value: true, Weight: 0.9},
			{Field: "sophistication", Operator: ">=", Value: 0.5, Weight: 0.6},
		},
		ResponseTypes:  []string{"evasion_aware_response", "encoding_mirror", "technique_reflection"},
		Adaptiveness:   0.8,
		LearningWeight: 0.7,
		Effectiveness:  0.7,
		Parameters: map[string]interface{}{
			"mirror_encoding":     true,
			"technique_analysis":  true,
			"counter_evasion":     true,
			"learning_emphasis":   0.8,
		},
	})
	
	// Reconnaissance strategy
	rse.strategies = append(rse.strategies, ResponseStrategy{
		Name:        "Information_Control",
		Description: "Controlled information disclosure for reconnaissance",
		Conditions: []StrategyCondition{
			{Field: "attack_type", Operator: "in", Value: []string{"reconnaissance", "scanning"}, Weight: 0.8},
			{Field: "threat_level", Operator: "in", Value: []string{"low", "medium"}, Weight: 0.6},
		},
		ResponseTypes:  []string{"selective_disclosure", "false_information", "guided_exploration"},
		Adaptiveness:   0.5,
		LearningWeight: 0.6,
		Effectiveness:  0.6,
		Parameters: map[string]interface{}{
			"information_level":   "partial",
			"false_data_ratio":    0.3,
			"exploration_paths":   []string{"/admin", "/backup", "/config"},
			"honeypot_breadcrumbs": true,
		},
	})
	
	// Professional penetration tester strategy
	rse.strategies = append(rse.strategies, ResponseStrategy{
		Name:        "Professional_Engagement",
		Description: "Sophisticated responses for professional testers",
		Conditions: []StrategyCondition{
			{Field: "attacker_profile", Operator: "==", Value: "professional_penetration_tester", Weight: 0.9},
			{Field: "skill_level", Operator: "in", Value: []string{"expert", "advanced"}, Weight: 0.8},
		},
		ResponseTypes:  []string{"realistic_vulnerability", "deep_honeypot", "professional_challenge"},
		Adaptiveness:   0.95,
		LearningWeight: 0.9,
		Effectiveness:  0.85,
		Parameters: map[string]interface{}{
			"realism_level":       0.95,
			"vulnerability_depth": "deep",
			"challenge_level":     "expert",
			"interaction_quality": "high",
		},
	})
	
	// Default fallback strategy
	rse.defaultStrategy = ResponseStrategy{
		Name:        "Standard_Response",
		Description: "Standard honeypot response for unknown contexts",
		Conditions:  []StrategyCondition{},
		ResponseTypes: []string{"basic_honeypot", "standard_error", "generic_response"},
		Adaptiveness:   0.3,
		LearningWeight: 0.4,
		Effectiveness:  0.5,
		Parameters: map[string]interface{}{
			"response_type":    "basic",
			"learning_enabled": true,
			"data_collection":  true,
		},
	}
}

// SelectStrategy selects the best response strategy based on context
func (rse *ResponseStrategyEngine) SelectStrategy(context *AttackContext) *ResponseStrategy {
	bestStrategy := &rse.defaultStrategy
	bestScore := 0.0
	
	// Evaluate each strategy against the context
	for _, strategy := range rse.strategies {
		score := rse.evaluateStrategy(strategy, context)
		
		// Apply learning adjustments if adaptive mode is enabled
		if rse.adaptiveEnabled {
			score = rse.applyLearningAdjustments(strategy, context, score)
		}
		
		if score > bestScore {
			bestScore = score
			bestStrategy = &strategy
		}
	}
	
	return bestStrategy
}

// evaluateStrategy evaluates how well a strategy matches the context
func (rse *ResponseStrategyEngine) evaluateStrategy(strategy ResponseStrategy, context *AttackContext) float64 {
	if len(strategy.Conditions) == 0 {
		return 0.1 // Low score for strategies without conditions
	}
	
	totalWeight := 0.0
	matchedWeight := 0.0
	
	for _, condition := range strategy.Conditions {
		totalWeight += condition.Weight
		
		if rse.evaluateCondition(condition, context) {
			matchedWeight += condition.Weight
		}
	}
	
	if totalWeight == 0 {
		return 0.0
	}
	
	// Base score from condition matching
	baseScore := matchedWeight / totalWeight
	
	// Apply strategy effectiveness
	adjustedScore := baseScore * strategy.Effectiveness
	
	// Apply randomness for exploration
	if rse.adaptiveEnabled {
		explorationFactor := 0.1 * rand.Float64()
		adjustedScore += explorationFactor
	}
	
	return adjustedScore
}

// evaluateCondition evaluates a single condition against the context
func (rse *ResponseStrategyEngine) evaluateCondition(condition StrategyCondition, context *AttackContext) bool {
	var contextValue interface{}
	
	// Extract the relevant value from context
	switch condition.Field {
	case "sophistication":
		contextValue = context.Sophistication
	case "threat_level":
		contextValue = context.ThreatLevel
	case "attacker_profile":
		contextValue = context.AttackerProfile
	case "evasion":
		contextValue = context.Evasion
	case "attack_type":
		contextValue = context.AttackType
	case "skill_level":
		contextValue = context.BehavioralMetrics.SkillLevel
	case "automation_level":
		contextValue = context.BehavioralMetrics.AutomationLevel
	case "persistence":
		contextValue = context.Persistence
	default:
		return false
	}
	
	// Evaluate based on operator
	switch condition.Operator {
	case "==":
		return contextValue == condition.Value
	case "!=":
		return contextValue != condition.Value
	case ">=":
		if cv, ok := contextValue.(float64); ok {
			if tv, ok := condition.Value.(float64); ok {
				return cv >= tv
			}
		}
	case "<=":
		if cv, ok := contextValue.(float64); ok {
			if tv, ok := condition.Value.(float64); ok {
				return cv <= tv
			}
		}
	case ">":
		if cv, ok := contextValue.(float64); ok {
			if tv, ok := condition.Value.(float64); ok {
				return cv > tv
			}
		}
	case "<":
		if cv, ok := contextValue.(float64); ok {
			if tv, ok := condition.Value.(float64); ok {
				return cv < tv
			}
		}
	case "in":
		if values, ok := condition.Value.([]string); ok {
			if cv, ok := contextValue.(string); ok {
				for _, v := range values {
					if cv == v {
						return true
					}
				}
			}
		}
	case "contains":
		if cv, ok := contextValue.(string); ok {
			if tv, ok := condition.Value.(string); ok {
				return strings.Contains(cv, tv)
			}
		}
	}
	
	return false
}

// applyLearningAdjustments applies learning-based adjustments to strategy scores
func (rse *ResponseStrategyEngine) applyLearningAdjustments(strategy ResponseStrategy, context *AttackContext, baseScore float64) float64 {
	// Get historical performance for this strategy
	sessionID := rse.generateSessionKey(context)
	history := rse.strategyHistory[sessionID]
	
	if len(history) == 0 {
		return baseScore
	}
	
	// Calculate average effectiveness for this strategy
	strategyEffectiveness := 0.0
	strategyCount := 0
	
	for _, result := range history {
		if result.Strategy.Name == strategy.Name {
			strategyEffectiveness += result.Effectiveness
			strategyCount++
		}
	}
	
	if strategyCount == 0 {
		return baseScore
	}
	
	avgEffectiveness := strategyEffectiveness / float64(strategyCount)
	
	// Apply learning adjustment
	learningAdjustment := (avgEffectiveness - 0.5) * strategy.LearningWeight * rse.learningRate
	adjustedScore := baseScore + learningAdjustment
	
	// Ensure score stays within bounds
	if adjustedScore < 0 {
		adjustedScore = 0
	}
	if adjustedScore > 1 {
		adjustedScore = 1
	}
	
	return adjustedScore
}

// RecordStrategyResult records the result of applying a strategy for learning
func (rse *ResponseStrategyEngine) RecordStrategyResult(context *AttackContext, strategy ResponseStrategy, response ContextualResponse, effectiveness float64) {
	sessionKey := rse.generateSessionKey(context)
	
	result := StrategyResult{
		Timestamp:        time.Now(),
		Strategy:         strategy,
		Context:          *context,
		Response:         response,
		Effectiveness:    effectiveness,
		AttackerReaction: "unknown", // Would be updated based on follow-up analysis
		SessionContinued: false,     // Would be updated based on session tracking
		LearningValue:    rse.calculateLearningValue(effectiveness, strategy),
	}
	
	rse.strategyHistory[sessionKey] = append(rse.strategyHistory[sessionKey], result)
	
	// Update strategy effectiveness if adaptive learning is enabled
	if rse.adaptiveEnabled {
		rse.updateStrategyEffectiveness(strategy.Name, effectiveness)
	}
}

// calculateLearningValue calculates the learning value from a strategy result
func (rse *ResponseStrategyEngine) calculateLearningValue(effectiveness float64, strategy ResponseStrategy) float64 {
	// Learning value is higher for more adaptive strategies and extreme effectiveness
	adaptiveBonus := strategy.Adaptiveness * 0.3
	
	// Extreme effectiveness (very high or very low) provides more learning value
	extremeBonus := math.Abs(effectiveness-0.5) * 0.4
	
	learningValue := effectiveness + adaptiveBonus + extremeBonus
	
	// Apply learning weight
	learningValue *= strategy.LearningWeight
	
	return math.Min(learningValue, 1.0)
}

// updateStrategyEffectiveness updates the effectiveness of a strategy based on results
func (rse *ResponseStrategyEngine) updateStrategyEffectiveness(strategyName string, newEffectiveness float64) {
	for i, strategy := range rse.strategies {
		if strategy.Name == strategyName {
			// Apply exponential moving average
			alpha := rse.learningRate
			rse.strategies[i].Effectiveness = alpha*newEffectiveness + (1-alpha)*strategy.Effectiveness
			break
		}
	}
}

// GetStrategyRecommendations provides recommendations for strategy selection
func (rse *ResponseStrategyEngine) GetStrategyRecommendations(context *AttackContext) []string {
	recommendations := []string{}
	
	// Analyze context for specific recommendations
	if context.Sophistication > 0.8 {
		recommendations = append(recommendations, "Consider advanced engagement strategies")
		recommendations = append(recommendations, "Deploy sophisticated honeypot responses")
	}
	
	if context.Evasion {
		recommendations = append(recommendations, "Apply evasion-aware counter-strategies")
		recommendations = append(recommendations, "Implement technique-specific responses")
	}
	
	if context.ThreatLevel == "critical" {
		recommendations = append(recommendations, "Prioritize threat containment strategies")
		recommendations = append(recommendations, "Enhance data collection and analysis")
	}
	
	// Behavioral-based recommendations
	switch context.BehavioralMetrics.AutomationLevel {
	case "automated":
		recommendations = append(recommendations, "Deploy scanner disruption techniques")
		recommendations = append(recommendations, "Implement rate limiting strategies")
	case "manual":
		recommendations = append(recommendations, "Engage with interactive responses")
		recommendations = append(recommendations, "Provide realistic vulnerability simulations")
	}
	
	return recommendations
}

// GetStrategyEffectiveness returns the current effectiveness of all strategies
func (rse *ResponseStrategyEngine) GetStrategyEffectiveness() map[string]float64 {
	effectiveness := make(map[string]float64)
	
	for _, strategy := range rse.strategies {
		effectiveness[strategy.Name] = strategy.Effectiveness
	}
	
	return effectiveness
}

// GetStrategyHistory returns the strategy application history
func (rse *ResponseStrategyEngine) GetStrategyHistory(sessionKey string) []StrategyResult {
	if history, exists := rse.strategyHistory[sessionKey]; exists {
		return history
	}
	return []StrategyResult{}
}

// EnableAdaptiveLearning enables or disables adaptive learning
func (rse *ResponseStrategyEngine) EnableAdaptiveLearning(enabled bool) {
	rse.adaptiveEnabled = enabled
}

// SetLearningRate sets the learning rate for adaptive strategies
func (rse *ResponseStrategyEngine) SetLearningRate(rate float64) {
	if rate >= 0 && rate <= 1 {
		rse.learningRate = rate
	}
}

// AddCustomStrategy adds a custom response strategy
func (rse *ResponseStrategyEngine) AddCustomStrategy(strategy ResponseStrategy) {
	rse.strategies = append(rse.strategies, strategy)
}

// Helper methods

func (rse *ResponseStrategyEngine) generateSessionKey(context *AttackContext) string {
	// Generate a session key based on context characteristics
	return fmt.Sprintf("%s_%s_%s", 
		context.AttackerProfile, 
		context.ThreatLevel, 
		context.AttackType)
}

// ExportStrategyData exports strategy data for analysis and research
func (rse *ResponseStrategyEngine) ExportStrategyData() map[string]interface{} {
	return map[string]interface{}{
		"strategies":        rse.strategies,
		"strategy_history":  rse.strategyHistory,
		"learning_rate":     rse.learningRate,
		"adaptive_enabled":  rse.adaptiveEnabled,
		"default_strategy":  rse.defaultStrategy,
		"exported_at":       time.Now(),
	}
}