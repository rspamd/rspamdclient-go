// Package config provides configuration for the Rspamd client
package config

// TLSSettings represents custom TLS settings for the Rspamd client
type TLSSettings struct {
	// Path to the TLS certificate file
	CertPath string
	// Path to the TLS key file
	KeyPath string
	// Optional path to the TLS CA file
	CAPath *string
}

// ProxyConfig represents proxy configuration for the Rspamd client
type ProxyConfig struct {
	// Proxy server URL
	ProxyURL string
	// Optional username for proxy authentication
	Username *string
	// Optional password for proxy authentication
	Password *string
}

// EnvelopeData represents email envelope data
type EnvelopeData struct {
	// Sender email address
	From *string
	// Recipients email addresses
	Rcpt []string
	// Optional IP address of the sender
	IP *string
	// Optional user
	User *string
	// Optional HELO string
	Helo *string
	// Optional hostname
	Hostname *string
	// Optional additional headers
	AdditionalHeaders map[string]string
}

// ToHeaders converts EnvelopeData to HTTP headers map
func (e *EnvelopeData) ToHeaders() map[string]string {
	headers := make(map[string]string)

	// Copy additional headers first
	if e.AdditionalHeaders != nil {
		for k, v := range e.AdditionalHeaders {
			headers[k] = v
		}
	}

	// Add envelope data
	if e.From != nil {
		headers["From"] = *e.From
	}
	if e.IP != nil {
		headers["IP"] = *e.IP
	}
	if e.User != nil {
		headers["User"] = *e.User
	}
	if e.Helo != nil {
		headers["Helo"] = *e.Helo
	}
	if e.Hostname != nil {
		headers["Hostname"] = *e.Hostname
	}

	// Handle multiple recipients
	for _, rcpt := range e.Rcpt {
		headers["Rcpt"] = rcpt // Note: This will overwrite if multiple, might need array handling
	}

	return headers
}

// Config represents configuration for Rspamd client
type Config struct {
	// Base URL of Rspamd server
	BaseURL string
	// Optional API key for authentication
	Password *string
	// Timeout duration for requests in seconds
	Timeout float64
	// Number of retries for requests
	Retries uint32
	// Custom TLS settings
	TLSSettings *TLSSettings
	// Proxy configuration
	ProxyConfig *ProxyConfig
	// Use zstd compression
	ZSTD bool
	// Encryption key if using native HTTPCrypt encryption (must be in Rspamd base32 format)
	EncryptionKey *string
}

// NewConfig creates a new Config with default values
func NewConfig(baseURL string) *Config {
	return &Config{
		BaseURL: baseURL,
		Timeout: 30.0,
		Retries: 1,
		ZSTD:    true,
	}
}

// WithPassword sets the password for authentication
func (c *Config) WithPassword(password string) *Config {
	c.Password = &password
	return c
}

// WithTimeout sets the timeout for requests
func (c *Config) WithTimeout(timeout float64) *Config {
	c.Timeout = timeout
	return c
}

// WithRetries sets the number of retries
func (c *Config) WithRetries(retries uint32) *Config {
	c.Retries = retries
	return c
}

// WithTLSSettings sets custom TLS settings
func (c *Config) WithTLSSettings(tls *TLSSettings) *Config {
	c.TLSSettings = tls
	return c
}

// WithProxyConfig sets proxy configuration
func (c *Config) WithProxyConfig(proxy *ProxyConfig) *Config {
	c.ProxyConfig = proxy
	return c
}

// WithZSTD enables or disables ZSTD compression
func (c *Config) WithZSTD(enabled bool) *Config {
	c.ZSTD = enabled
	return c
}

// WithEncryptionKey sets the encryption key for HTTPCrypt
func (c *Config) WithEncryptionKey(key string) *Config {
	c.EncryptionKey = &key
	return c
}

// NewEnvelopeData creates a new EnvelopeData with default values
func NewEnvelopeData() *EnvelopeData {
	return &EnvelopeData{
		Rcpt:              make([]string, 0),
		AdditionalHeaders: make(map[string]string),
	}
}

// WithFrom sets the sender email address
func (e *EnvelopeData) WithFrom(from string) *EnvelopeData {
	e.From = &from
	return e
}

// WithRcpt adds a recipient email address
func (e *EnvelopeData) WithRcpt(rcpt string) *EnvelopeData {
	e.Rcpt = append(e.Rcpt, rcpt)
	return e
}

// WithIP sets the sender IP address
func (e *EnvelopeData) WithIP(ip string) *EnvelopeData {
	e.IP = &ip
	return e
}

// WithUser sets the user
func (e *EnvelopeData) WithUser(user string) *EnvelopeData {
	e.User = &user
	return e
}

// WithHelo sets the HELO string
func (e *EnvelopeData) WithHelo(helo string) *EnvelopeData {
	e.Helo = &helo
	return e
}

// WithHostname sets the hostname
func (e *EnvelopeData) WithHostname(hostname string) *EnvelopeData {
	e.Hostname = &hostname
	return e
}

// WithHeader adds an additional header
func (e *EnvelopeData) WithHeader(key, value string) *EnvelopeData {
	if e.AdditionalHeaders == nil {
		e.AdditionalHeaders = make(map[string]string)
	}
	e.AdditionalHeaders[key] = value
	return e
}
