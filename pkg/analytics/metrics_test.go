package analytics

import (
	"net/http"
	"strings"
	"testing"
)

func TestMetricsCalculator_DetectAttackVectors(t *testing.T) {
	calc := NewMetricsCalculator()
	
	tests := []struct {
		name     string
		url      string
		body     string
		expected []string
	}{
		{
			name:     "SQL injection in URL",
			url:      "?id=1' OR '1'='1",
			body:     "",
			expected: []string{"sql_injection"},
		},
		{
			name:     "XSS in body",
			url:      "",
			body:     "<script>alert('xss')</script>",
			expected: []string{"xss"},
		},
		{
			name:     "Directory traversal",
			url:      "?file=../../../etc/passwd",
			body:     "",
			expected: []string{"directory_traversal"},
		},
		{
			name:     "Multiple attack vectors",
			url:      "?id=1' AND 1=1",
			body:     "<script>alert(1)</script>",
			expected: []string{"sql_injection", "xss"},
		},
		{
			name:     "Clean request",
			url:      "?page=home",
			body:     "normal content",
			expected: []string{},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com"+tt.url, strings.NewReader(tt.body))
			result := calc.DetectAttackVectors(req, tt.body)
			
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d attack vectors, got %d", len(tt.expected), len(result))
				return
			}
			
			for _, expected := range tt.expected {
				found := false
				for _, actual := range result {
					if actual == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected attack vector %s not found in result", expected)
				}
			}
		})
	}
}

func TestMetricsCalculator_CalculatePayloadEntropy(t *testing.T) {
	calc := NewMetricsCalculator()
	
	tests := []struct {
		name     string
		payload  string
		minEntropy float64
		maxEntropy float64
	}{
		{
			name:       "Random string",
			payload:    "abcdefghijklmnopqrstuvwxyz",
			minEntropy: 4.0,
			maxEntropy: 5.0,
		},
		{
			name:       "Repeated characters",
			payload:    "aaaaaaaaaa",
			minEntropy: 0.0,
			maxEntropy: 1.0,
		},
		{
			name:       "Empty string",
			payload:    "",
			minEntropy: 0.0,
			maxEntropy: 0.0,
		},
		{
			name:       "High entropy (base64-like)",
			payload:    "SGVsbG8gV29ybGQhIVRoaXMgaXMgYSB0ZXN0",
			minEntropy: 5.0,
			maxEntropy: 7.0,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := calc.CalculatePayloadEntropy(tt.payload)
			if entropy < tt.minEntropy || entropy > tt.maxEntropy {
				t.Errorf("Entropy %f not in expected range [%f, %f]", entropy, tt.minEntropy, tt.maxEntropy)
			}
		})
	}
}

func TestMetricsCalculator_CalculateRiskScore(t *testing.T) {
	calc := NewMetricsCalculator()
	
	tests := []struct {
		name              string
		attackVectors     []string
		suspiciousPatterns []string
		entropy           float64
		expectedMin       float64
		expectedMax       float64
	}{
		{
			name:              "High risk",
			attackVectors:     []string{"sql_injection", "xss", "command_injection"},
			suspiciousPatterns: []string{"base64_encoding", "url_encoding"},
			entropy:           7.5,
			expectedMin:       10.0,
			expectedMax:       10.0, // Capped at 10
		},
		{
			name:              "Medium risk",
			attackVectors:     []string{"xss"},
			suspiciousPatterns: []string{"base64_encoding"},
			entropy:           5.0,
			expectedMin:       4.0,
			expectedMax:       6.0,
		},
		{
			name:              "Low risk",
			attackVectors:     []string{},
			suspiciousPatterns: []string{},
			entropy:           3.0,
			expectedMin:       0.0,
			expectedMax:       1.0,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := calc.CalculateRiskScore(tt.attackVectors, tt.suspiciousPatterns, tt.entropy)
			if score < tt.expectedMin || score > tt.expectedMax {
				t.Errorf("Risk score %f not in expected range [%f, %f]", score, tt.expectedMin, tt.expectedMax)
			}
		})
	}
}

func TestMetricsCalculator_CalculateRequestFingerprint(t *testing.T) {
	calc := NewMetricsCalculator()
	
	// Test that same requests produce same fingerprint
	req1, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req1.Header.Set("User-Agent", "test-agent")
	req1.Header.Set("Content-Type", "application/json")
	
	req2, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req2.Header.Set("User-Agent", "test-agent")
	req2.Header.Set("Content-Type", "application/json")
	
	fp1 := calc.CalculateRequestFingerprint(req1)
	fp2 := calc.CalculateRequestFingerprint(req2)
	
	if fp1 != fp2 {
		t.Errorf("Expected same fingerprints for identical requests, got %s and %s", fp1, fp2)
	}
	
	// Test that different requests produce different fingerprints
	req3, _ := http.NewRequest("POST", "http://example.com/test", nil)
	req3.Header.Set("User-Agent", "different-agent")
	
	fp3 := calc.CalculateRequestFingerprint(req3)
	
	if fp1 == fp3 {
		t.Errorf("Expected different fingerprints for different requests, but both were %s", fp1)
	}
}