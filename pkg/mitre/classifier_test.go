package mitre

import (
	"net/http"
	"strings"
	"testing"
)

func TestClassifier_LoadTechniques(t *testing.T) {
	classifier, err := NewClassifier("")
	if err != nil {
		t.Fatalf("Failed to create classifier: %v", err)
	}
	
	// Should have loaded some techniques
	techniques := classifier.GetAllTechniques()
	if len(techniques) == 0 {
		t.Error("No techniques loaded")
	}
	
	// Check for key techniques
	if _, exists := techniques["T1190"]; !exists {
		t.Error("T1190 (Exploit Public-Facing Application) not loaded")
	}
}

func TestClassifier_ClassifyRequest_SQLInjection(t *testing.T) {
	classifier, err := NewClassifier("")
	if err != nil {
		t.Fatalf("Failed to create classifier: %v", err)
	}
	
	// Create SQL injection request
	req, _ := http.NewRequest("GET", "http://example.com/test?id=1' OR '1'='1", nil)
	body := ""
	attackVectors := []string{"sql_injection"}
	
	result := classifier.ClassifyRequest(req, body, attackVectors)
	
	// Should detect T1190 and related techniques
	if len(result.Matches) == 0 {
		t.Error("No techniques detected for SQL injection")
	}
	
	foundT1190 := false
	for _, match := range result.Matches {
		if match.Technique.ID == "T1190" {
			foundT1190 = true
			if match.Confidence < 0.5 {
				t.Errorf("Low confidence for T1190: %f", match.Confidence)
			}
		}
	}
	
	if !foundT1190 {
		t.Error("T1190 not detected for SQL injection")
	}
	
	if result.PrimaryTactic != "Initial Access" {
		t.Errorf("Expected Primary Tactic 'Initial Access', got '%s'", result.PrimaryTactic)
	}
}

func TestClassifier_ClassifyRequest_XSS(t *testing.T) {
	classifier, err := NewClassifier("")
	if err != nil {
		t.Fatalf("Failed to create classifier: %v", err)
	}
	
	// Create XSS request
	req, _ := http.NewRequest("POST", "http://example.com/comment", nil)
	body := "<script>alert('xss')</script>"
	attackVectors := []string{"xss"}
	
	result := classifier.ClassifyRequest(req, body, attackVectors)
	
	if len(result.Matches) == 0 {
		t.Error("No techniques detected for XSS")
	}
	
	// Should have evidence
	for _, match := range result.Matches {
		if len(match.Evidence) == 0 {
			t.Error("No evidence provided for XSS detection")
		}
	}
}

func TestClassifier_ClassifyRequest_DirectoryTraversal(t *testing.T) {
	classifier, err := NewClassifier("")
	if err != nil {
		t.Fatalf("Failed to create classifier: %v", err)
	}
	
	// Create directory traversal request
	req, _ := http.NewRequest("GET", "http://example.com/file?path=../../../etc/passwd", nil)
	body := ""
	attackVectors := []string{"directory_traversal"}
	
	result := classifier.ClassifyRequest(req, body, attackVectors)
	
	if len(result.Matches) == 0 {
		t.Error("No techniques detected for directory traversal")
	}
	
	// Should detect discovery-related techniques
	foundDiscovery := false
	for _, match := range result.Matches {
		if match.Technique.Tactic == "Discovery" {
			foundDiscovery = true
		}
	}
	
	if !foundDiscovery {
		t.Error("Discovery tactic not detected for directory traversal")
	}
}

func TestClassifier_ClassifyRequest_Scanner(t *testing.T) {
	classifier, err := NewClassifier("")
	if err != nil {
		t.Fatalf("Failed to create classifier: %v", err)
	}
	
	// Create scanner request
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("User-Agent", "Nikto/2.1.6")
	body := ""
	attackVectors := []string{}
	
	result := classifier.ClassifyRequest(req, body, attackVectors)
	
	// Should detect reconnaissance
	foundRecon := false
	for _, match := range result.Matches {
		if match.Technique.Tactic == "Reconnaissance" {
			foundRecon = true
		}
	}
	
	if !foundRecon {
		t.Error("Reconnaissance not detected for scanner user agent")
	}
}

func TestClassifier_ClassifyRequest_Clean(t *testing.T) {
	classifier, err := NewClassifier("")
	if err != nil {
		t.Fatalf("Failed to create classifier: %v", err)
	}
	
	// Create clean request
	req, _ := http.NewRequest("GET", "http://example.com/page?q=hello", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (normal browser)")
	body := "normal content"
	attackVectors := []string{}
	
	result := classifier.ClassifyRequest(req, body, attackVectors)
	
	// Should have low or no matches
	if result.OverallRisk > 2.0 {
		t.Errorf("High risk score for clean request: %f", result.OverallRisk)
	}
}

func TestClassifier_PatternMatching(t *testing.T) {
	classifier, err := NewClassifier("")
	if err != nil {
		t.Fatalf("Failed to create classifier: %v", err)
	}
	
	tests := []struct {
		name     string
		pattern  PatternMatcher
		request  *http.Request
		body     string
		expected bool
	}{
		{
			name: "URL regex match",
			pattern: PatternMatcher{
				Type:    "url",
				Pattern: "(?i)(union|select)",
				IsRegex: true,
			},
			request:  mustCreateRequest("GET", "http://test.com?q=UNION SELECT", ""),
			body:     "",
			expected: true,
		},
		{
			name: "Body literal match",
			pattern: PatternMatcher{
				Type:    "body",
				Pattern: "script",
				IsRegex: false,
			},
			request:  mustCreateRequest("POST", "http://test.com", ""),
			body:     "<script>alert(1)</script>",
			expected: true,
		},
		{
			name: "User-Agent match",
			pattern: PatternMatcher{
				Type:    "user_agent",
				Pattern: "(?i)nikto",
				IsRegex: true,
			},
			request:  mustCreateRequestWithUA("GET", "http://test.com", "", "Nikto/2.1.6"),
			body:     "",
			expected: true,
		},
		{
			name: "No match",
			pattern: PatternMatcher{
				Type:    "body",
				Pattern: "malicious",
				IsRegex: false,
			},
			request:  mustCreateRequest("GET", "http://test.com", ""),
			body:     "normal content",
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifier.evaluatePattern(tt.pattern, tt.request, tt.body, "test_pattern")
			if result != tt.expected {
				t.Errorf("Pattern evaluation failed: expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestClassifier_RiskCalculation(t *testing.T) {
	classifier, err := NewClassifier("")
	if err != nil {
		t.Fatalf("Failed to create classifier: %v", err)
	}
	
	// High risk attack
	req, _ := http.NewRequest("POST", "http://example.com/upload", nil)
	body := "<?php eval($_POST['cmd']); ?>"
	attackVectors := []string{"command_injection"}
	
	result := classifier.ClassifyRequest(req, body, attackVectors)
	
	if result.OverallRisk < 5.0 {
		t.Errorf("Expected high risk score, got %f", result.OverallRisk)
	}
}

// Helper functions for tests

func mustCreateRequest(method, url, body string) *http.Request {
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		panic(err)
	}
	return req
}

func mustCreateRequestWithUA(method, url, body, userAgent string) *http.Request {
	req := mustCreateRequest(method, url, body)
	req.Header.Set("User-Agent", userAgent)
	return req
}