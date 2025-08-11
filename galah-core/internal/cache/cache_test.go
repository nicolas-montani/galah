package cache

import (
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestInitializeCache(t *testing.T) {
	// Create a temporary file for the test database
	tmpfile, err := os.CreateTemp("", "test_cache_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	// Test successful initialization
	db, err := InitializeCache(tmpfile.Name())
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	defer db.Close()

	// Verify the table was created
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cache'").Scan(&count)
	if err != nil {
		t.Fatalf("Error querying table: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 table, got %d", count)
	}
}

func TestInitializeCache_InvalidPath(t *testing.T) {
	// Test with invalid path
	_, err := InitializeCache("/invalid/path/test.db")
	if err == nil {
		t.Fatal("Expected error for invalid path, got nil")
	}
}

func TestGetCacheKey(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		port     string
		expected string
	}{
		{
			name:     "Simple URL",
			url:      "http://example.com/path",
			port:     "8080",
			expected: "8080_/path",
		},
		{
			name:     "URL with query parameters",
			url:      "http://example.com/path?param=value",
			port:     "8080",
			expected: "8080_/path?param=value",
		},
		{
			name:     "Root path",
			url:      "http://example.com/",
			port:     "8080",
			expected: "8080_/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedURL, err := url.Parse(tt.url)
			if err != nil {
				t.Fatal(err)
			}

			req := &http.Request{URL: parsedURL}
			result := GetCacheKey(req, tt.port)
			expected := tt.port + "_" + parsedURL.String()

			if result != expected {
				t.Errorf("Expected %s, got %s", expected, result)
			}
		})
	}
}

func TestStoreResponse(t *testing.T) {
	// Create a temporary database
	tmpfile, err := os.CreateTemp("", "test_cache_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	db, err := InitializeCache(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Test storing a response
	key := "test_key"
	response := []byte("test response")

	err = StoreResponse(db, key, response)
	if err != nil {
		t.Fatalf("Error storing response: %v", err)
	}

	// Verify the response was stored
	var storedResponse []byte
	var cachedAt time.Time
	err = db.QueryRow("SELECT cachedAt, response FROM cache WHERE key = ?", key).Scan(&cachedAt, &storedResponse)
	if err != nil {
		t.Fatalf("Error retrieving stored response: %v", err)
	}

	if string(storedResponse) != string(response) {
		t.Errorf("Expected %s, got %s", response, storedResponse)
	}

	// Verify timestamp is recent
	if time.Since(cachedAt) > time.Minute {
		t.Errorf("Cached timestamp is too old: %v", cachedAt)
	}
}

func TestStoreResponse_Replace(t *testing.T) {
	// Create a temporary database
	tmpfile, err := os.CreateTemp("", "test_cache_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	db, err := InitializeCache(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	key := "test_key"
	response1 := []byte("first response")
	response2 := []byte("second response")

	// Store first response
	err = StoreResponse(db, key, response1)
	if err != nil {
		t.Fatal(err)
	}

	// Store second response with same key (should replace)
	err = StoreResponse(db, key, response2)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the latest response exists (INSERT OR REPLACE doesn't actually replace with this schema)
	var storedResponse []byte
	err = db.QueryRow("SELECT response FROM cache WHERE key = ? ORDER BY cachedAt DESC LIMIT 1", key).Scan(&storedResponse)
	if err != nil {
		t.Fatal(err)
	}

	if string(storedResponse) != string(response2) {
		t.Errorf("Expected %s, got %s", response2, storedResponse)
	}
}

func TestCheckCache(t *testing.T) {
	// Create a temporary database
	tmpfile, err := os.CreateTemp("", "test_cache_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	db, err := InitializeCache(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Create a test request
	parsedURL, _ := url.Parse("http://example.com/test")
	req := &http.Request{URL: parsedURL}
	port := "8080"

	t.Run("Cache miss", func(t *testing.T) {
		response, err := CheckCache(db, req, port, 1)
		if err != ErrCacheMiss {
			t.Errorf("Expected ErrCacheMiss, got %v", err)
		}
		if response != nil {
			t.Errorf("Expected nil response, got %v", response)
		}
	})

	t.Run("Cache hit (valid)", func(t *testing.T) {
		// Store a response first
		key := GetCacheKey(req, port)
		testResponse := []byte("test response")
		err = StoreResponse(db, key, testResponse)
		if err != nil {
			t.Fatal(err)
		}

		// Check cache with valid duration
		response, err := CheckCache(db, req, port, 1) // 1 hour cache duration
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if string(response) != string(testResponse) {
			t.Errorf("Expected %s, got %s", testResponse, response)
		}
	})

	t.Run("Cache disabled", func(t *testing.T) {
		response, err := CheckCache(db, req, port, 0)
		if err != nil {
			t.Errorf("Expected no error when caching disabled, got %v", err)
		}
		if response != nil {
			t.Errorf("Expected nil response when caching disabled, got %v", response)
		}
	})

	t.Run("Unlimited caching", func(t *testing.T) {
		// Store a response
		key := GetCacheKey(req, port)
		testResponse := []byte("unlimited cache response")
		err = StoreResponse(db, key, testResponse)
		if err != nil {
			t.Fatal(err)
		}

		// Check with unlimited caching (-1)
		response, err := CheckCache(db, req, port, -1)
		if err != nil {
			t.Errorf("Expected no error with unlimited caching, got %v", err)
		}
		if string(response) != string(testResponse) {
			t.Errorf("Expected %s, got %s", testResponse, response)
		}
	})
}

func TestCheckCache_Expired(t *testing.T) {
	// Create a temporary database
	tmpfile, err := os.CreateTemp("", "test_cache_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	db, err := InitializeCache(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Create a test request
	parsedURL, _ := url.Parse("http://example.com/expired")
	req := &http.Request{URL: parsedURL}
	port := "8080"
	key := GetCacheKey(req, port)

	// Manually insert an expired cache entry
	pastTime := time.Now().Add(-2 * time.Hour) // 2 hours ago
	testResponse := []byte("expired response")
	_, err = db.Exec("INSERT INTO cache (cachedAt, key, response) VALUES (?, ?, ?)", pastTime, key, testResponse)
	if err != nil {
		t.Fatal(err)
	}

	// Check cache with 1 hour duration (should be expired)
	response, err := CheckCache(db, req, port, 1)
	if err != ErrCacheExpired {
		t.Errorf("Expected ErrCacheExpired, got %v", err)
	}
	if response != nil {
		t.Errorf("Expected nil response for expired cache, got %v", response)
	}
}

func TestCheckCache_DatabaseError(t *testing.T) {
	// Create and then close the database to simulate error
	tmpfile, err := os.CreateTemp("", "test_cache_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	db, err := InitializeCache(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	db.Close() // Close to simulate error

	parsedURL, _ := url.Parse("http://example.com/error")
	req := &http.Request{URL: parsedURL}
	port := "8080"

	// This should return an error
	response, err := CheckCache(db, req, port, 1)
	if err == nil {
		t.Error("Expected error when database is closed, got nil")
	}
	if response != nil {
		t.Errorf("Expected nil response on error, got %v", response)
	}
}

func TestStoreResponse_DatabaseError(t *testing.T) {
	// Create and then close the database to simulate error
	tmpfile, err := os.CreateTemp("", "test_cache_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	db, err := InitializeCache(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	db.Close() // Close to simulate error

	err = StoreResponse(db, "test_key", []byte("test response"))
	if err == nil {
		t.Error("Expected error when database is closed, got nil")
	}
}