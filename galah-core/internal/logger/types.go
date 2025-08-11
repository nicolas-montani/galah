package logger

import (
	"os"
	"time"

	"github.com/0x4d31/galah/pkg/enrich"
	"github.com/0x4d31/galah/pkg/llm"
	cblog "github.com/charmbracelet/log"
)

// ELKConfig holds configuration for ELK Stack integration
type ELKConfig struct {
	Enabled      bool   `json:"enabled"`
	LogstashHost string `json:"logstash_host,omitempty"`
	LogstashPort int    `json:"logstash_port,omitempty"`
}

// Logger contains the components for logging.
type Logger struct {
	EnrichCache *enrich.Enricher
	Sessionizer *Sessionizer
	EventLogger *cblog.Logger
	EventFile   *os.File
	LLMConfig   llm.Config
	Logger      *cblog.Logger
	ELKConfig   *ELKConfig
}

// HTTPRequest contains information about the HTTP request.
type HTTPRequest struct {
	Body                string            `json:"body"`
	BodySha256          string            `json:"bodySha256"`
	Headers             map[string]string `json:"headers"`
	HeadersSorted       string            `json:"headersSorted"`
	HeadersSortedSha256 string            `json:"headersSortedSha256"`
	Method              string            `json:"method"`
	ProtocolVersion     string            `json:"protocolVersion"`
	Request             string            `json:"request"`
	SessionID           string            `json:"sessionID"`
	UserAgent           string            `json:"userAgent"`
	// Research-focused fields
	RequestSize         int64             `json:"requestSize"`
	ContentType         string            `json:"contentType"`
	RequestFingerprint  string            `json:"requestFingerprint"`
	AttackVectors       []string          `json:"attackVectors,omitempty"`
	SuspiciousPatterns  []string          `json:"suspiciousPatterns,omitempty"`
	// ELK-optimized fields
	Timestamp           string            `json:"@timestamp"`
	RemoteAddr          string            `json:"remoteAddr"`
	RequestLength       int64             `json:"requestLength"`
}

// ResponseMetadata holds metadata about the generated response
type ResponseMetadata struct {
	GenerationSource    string        `json:"generationSource"`
	Info                LLMInfo       `json:"info,omitempty"`
	ProcessingTime      time.Duration `json:"processingTimeMs"`
	PromptTokens        int           `json:"promptTokens,omitempty"`
	CompletionTokens    int           `json:"completionTokens,omitempty"`
	CacheHit           bool          `json:"cacheHit"`
	ResponseQuality    float64       `json:"responseQuality,omitempty"`
	ContextAdaptation  string        `json:"contextAdaptation,omitempty"`
}

// LLMInfo holds information about the large language model
type LLMInfo struct {
	Model       string  `json:"model,omitempty"`
	Provider    string  `json:"provider,omitempty"`
	Temperature float64 `json:"temperature,omitempty"`
}

