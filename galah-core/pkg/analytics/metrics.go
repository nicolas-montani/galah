package analytics

import (
	"crypto/sha256"
	"fmt"
	"math"
	"net/http"
	"strings"
)

// MetricsCalculator provides methods for calculating research metrics
type MetricsCalculator struct{}

// NewMetricsCalculator creates a new metrics calculator
func NewMetricsCalculator() *MetricsCalculator {
	return &MetricsCalculator{}
}

// CalculateRequestFingerprint generates a unique fingerprint for the request
func (mc *MetricsCalculator) CalculateRequestFingerprint(r *http.Request) string {
	// Create fingerprint based on method, headers, and structural characteristics
	var components []string
	
	// Add method
	components = append(components, r.Method)
	
	// Add sorted header names (not values for privacy)
	var headerNames []string
	for name := range r.Header {
		headerNames = append(headerNames, strings.ToLower(name))
	}
	components = append(components, strings.Join(headerNames, ","))
	
	// Add content type
	components = append(components, r.Header.Get("Content-Type"))
	
	// Add user agent pattern (simplified)
	ua := r.Header.Get("User-Agent")
	if ua != "" {
		// Extract browser/tool signature
		if strings.Contains(ua, "curl") {
			components = append(components, "curl")
		} else if strings.Contains(ua, "wget") {
			components = append(components, "wget")
		} else if strings.Contains(ua, "python") {
			components = append(components, "python")
		} else if strings.Contains(ua, "Mozilla") {
			components = append(components, "browser")
		} else {
			components = append(components, "custom")
		}
	}
	
	fingerprint := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(fingerprint))
	return fmt.Sprintf("%x", hash[:8]) // First 8 bytes for brevity
}

// DetectAttackVectors analyzes the request for common attack patterns
func (mc *MetricsCalculator) DetectAttackVectors(r *http.Request, body string) []string {
	var vectors []string
	
	// SQL Injection patterns
	if mc.containsSQLInjection(r.URL.RawQuery + body) {
		vectors = append(vectors, "sql_injection")
	}
	
	// XSS patterns
	if mc.containsXSS(r.URL.RawQuery + body) {
		vectors = append(vectors, "xss")
	}
	
	// Command injection
	if mc.containsCommandInjection(r.URL.RawQuery + body) {
		vectors = append(vectors, "command_injection")
	}
	
	// Directory traversal
	if mc.containsDirectoryTraversal(r.URL.Path + r.URL.RawQuery) {
		vectors = append(vectors, "directory_traversal")
	}
	
	// File inclusion
	if mc.containsFileInclusion(r.URL.RawQuery + body) {
		vectors = append(vectors, "file_inclusion")
	}
	
	// XXE (XML External Entity)
	if strings.Contains(r.Header.Get("Content-Type"), "xml") && mc.containsXXE(body) {
		vectors = append(vectors, "xxe")
	}
	
	// SSRF (Server-Side Request Forgery)
	if mc.containsSSRF(r.URL.RawQuery + body) {
		vectors = append(vectors, "ssrf")
	}
	
	// LDAP injection
	if mc.containsLDAPInjection(r.URL.RawQuery + body) {
		vectors = append(vectors, "ldap_injection")
	}
	
	return vectors
}

// DetectSuspiciousPatterns identifies suspicious but not necessarily malicious patterns
func (mc *MetricsCalculator) DetectSuspiciousPatterns(r *http.Request, body string) []string {
	var patterns []string
	
	fullContent := r.URL.RawQuery + body + strings.Join(r.Header["User-Agent"], "")
	
	// Base64 encoded content
	if mc.containsBase64(fullContent) {
		patterns = append(patterns, "base64_encoding")
	}
	
	// URL encoding patterns
	if mc.containsURLEncoding(fullContent) {
		patterns = append(patterns, "url_encoding")
	}
	
	// Unicode escaping
	if mc.containsUnicodeEscaping(fullContent) {
		patterns = append(patterns, "unicode_escaping")
	}
	
	// Multiple encoding layers
	if mc.containsDoubleEncoding(fullContent) {
		patterns = append(patterns, "double_encoding")
	}
	
	// Unusual headers
	if mc.hasUnusualHeaders(r) {
		patterns = append(patterns, "unusual_headers")
	}
	
	// Scanner signatures
	if mc.isKnownScanner(r.Header.Get("User-Agent")) {
		patterns = append(patterns, "automated_scanner")
	}
	
	// Unusual HTTP methods
	if mc.isUnusualMethod(r.Method) {
		patterns = append(patterns, "unusual_method")
	}
	
	return patterns
}

// CalculatePayloadEntropy calculates the entropy of the request payload
func (mc *MetricsCalculator) CalculatePayloadEntropy(data string) float64 {
	if len(data) == 0 {
		return 0.0
	}
	
	// Count character frequencies
	freq := make(map[rune]int)
	for _, char := range data {
		freq[char]++
	}
	
	// Calculate entropy
	var entropy float64
	length := float64(len(data))
	
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}
	
	return entropy
}

// Helper methods for attack vector detection

func (mc *MetricsCalculator) containsSQLInjection(content string) bool {
	patterns := []string{
		"'", "\"", ";", "--", "/*", "*/",
		"union", "select", "insert", "update", "delete", "drop",
		"exec", "execute", "sp_", "xp_", "0x",
	}
	
	lower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func (mc *MetricsCalculator) containsXSS(content string) bool {
	patterns := []string{
		"<script", "</script>", "javascript:", "onload=", "onerror=",
		"onclick=", "onmouseover=", "alert(", "confirm(", "prompt(",
		"document.cookie", "window.location", "eval(",
	}
	
	lower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func (mc *MetricsCalculator) containsCommandInjection(content string) bool {
	patterns := []string{
		"|", "&&", "||", ";", "`", "$(", "${",
		"/bin/", "/usr/bin/", "cmd.exe", "powershell",
		"bash", "sh", "zsh", "nc ", "netcat",
		"wget ", "curl ", "ping ", "nslookup",
	}
	
	lower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func (mc *MetricsCalculator) containsDirectoryTraversal(content string) bool {
	patterns := []string{
		"../", "..\\", "....//", "....\\\\",
		"%2e%2e%2f", "%2e%2e%5c", "%252e%252e%252f",
		"/etc/passwd", "/etc/shadow", "c:\\windows\\",
	}
	
	lower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func (mc *MetricsCalculator) containsFileInclusion(content string) bool {
	patterns := []string{
		"file://", "php://", "data://", "expect://",
		"include=", "require=", "page=", "file=",
		"path=", "template=", "document=",
	}
	
	lower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func (mc *MetricsCalculator) containsXXE(content string) bool {
	patterns := []string{
		"<!entity", "<!doctype", "system ", "public ",
		"file://", "http://", "https://", "ftp://",
	}
	
	lower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func (mc *MetricsCalculator) containsSSRF(content string) bool {
	patterns := []string{
		"localhost", "127.0.0.1", "0.0.0.0", "::1",
		"169.254.169.254", "metadata", "169.254",
		"file://", "gopher://", "dict://",
	}
	
	lower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func (mc *MetricsCalculator) containsLDAPInjection(content string) bool {
	patterns := []string{
		"*(", "*)", "(&", "(|", "(!", "(&(", "(|(", "(!(",
		"objectclass=", "cn=", "uid=", "ou=", "dc=",
	}
	
	lower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func (mc *MetricsCalculator) containsBase64(content string) bool {
	// Look for base64 patterns
	patterns := []string{
		"base64", "btoa(", "atob(",
	}
	
	lower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	
	// Check for base64-like strings (length multiple of 4, valid chars)
	if len(content) > 20 && len(content)%4 == 0 {
		validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
		validCount := 0
		for _, char := range content {
			if strings.ContainsRune(validChars, char) {
				validCount++
			}
		}
		if float64(validCount)/float64(len(content)) > 0.9 {
			return true
		}
	}
	
	return false
}

func (mc *MetricsCalculator) containsURLEncoding(content string) bool {
	return strings.Contains(content, "%") && 
		   (strings.Contains(content, "%20") || 
		    strings.Contains(content, "%3C") || 
		    strings.Contains(content, "%3E"))
}

func (mc *MetricsCalculator) containsUnicodeEscaping(content string) bool {
	return strings.Contains(content, "\\u") || strings.Contains(content, "&#x")
}

func (mc *MetricsCalculator) containsDoubleEncoding(content string) bool {
	return strings.Contains(content, "%25") // URL-encoded %
}

func (mc *MetricsCalculator) hasUnusualHeaders(r *http.Request) bool {
	unusualHeaders := []string{
		"x-forwarded-for", "x-real-ip", "x-originating-ip",
		"x-remote-ip", "x-remote-addr", "x-cluster-client-ip",
	}
	
	for _, header := range unusualHeaders {
		if r.Header.Get(header) != "" {
			return true
		}
	}
	return false
}

func (mc *MetricsCalculator) isKnownScanner(userAgent string) bool {
	scanners := []string{
		"nmap", "masscan", "zmap", "nikto", "dirb", "gobuster",
		"sqlmap", "burp", "owasp", "nessus", "openvas",
		"nuclei", "ffuf", "dirsearch", "wpscan",
	}
	
	lower := strings.ToLower(userAgent)
	for _, scanner := range scanners {
		if strings.Contains(lower, scanner) {
			return true
		}
	}
	return false
}

func (mc *MetricsCalculator) isUnusualMethod(method string) bool {
	common := map[string]bool{
		"GET": true, "POST": true, "HEAD": true, "OPTIONS": true,
	}
	return !common[method]
}

// CalculateRiskScore calculates an overall risk score for the request
func (mc *MetricsCalculator) CalculateRiskScore(attackVectors, suspiciousPatterns []string, entropy float64) float64 {
	score := 0.0
	
	// Base score from attack vectors
	score += float64(len(attackVectors)) * 3.0
	
	// Additional score from suspicious patterns
	score += float64(len(suspiciousPatterns)) * 1.5
	
	// Entropy contribution (higher entropy = potentially more suspicious)
	if entropy > 6.0 {
		score += (entropy - 6.0) * 0.5
	}
	
	// Normalize to 0-10 scale
	if score > 10.0 {
		score = 10.0
	}
	
	return score
}