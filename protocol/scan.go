package protocol

// RspamdScanReply represents the response from Rspamd scan
type RspamdScanReply struct {
	// If message has been skipped
	IsSkipped bool `json:"is_skipped,omitempty"`
	// Scan score
	Score float64 `json:"score,omitempty"`
	// Required score (legacy)
	RequiredScore float64 `json:"required_score,omitempty"`
	// Action to take
	Action string `json:"action,omitempty"`
	// Action thresholds
	Thresholds map[string]float64 `json:"thresholds,omitempty"`
	// Symbols detected
	Symbols map[string]Symbol `json:"symbols,omitempty"`
	// Messages
	Messages map[string]string `json:"messages,omitempty"`
	// URLs
	URLs []string `json:"urls,omitempty"`
	// Emails
	Emails []string `json:"emails,omitempty"`
	// Message id
	MessageID string `json:"message-id,omitempty"`
	// Real time of scan
	TimeReal float64 `json:"time_real,omitempty"`
	// Milter actions block
	Milter *Milter `json:"milter,omitempty"`
	// Filename
	Filename string `json:"filename,omitempty"`
	// Scan time
	ScanTime float64 `json:"scan_time,omitempty"`
}

// Symbol structure
type Symbol struct {
	Name        string    `json:"name,omitempty"`
	Score       float64   `json:"score,omitempty"`
	MetricScore float64   `json:"metric_score,omitempty"`
	Description *string   `json:"description,omitempty"`
	Options     *[]string `json:"options,omitempty"`
}

// Milter actions block
type Milter struct {
	AddHeaders    map[string]MailHeader `json:"add_headers,omitempty"`
	RemoveHeaders map[string]int        `json:"remove_headers,omitempty"`
}

// MailHeader represents a milter header action
type MailHeader struct {
	Value string `json:"value,omitempty"`
	Order int    `json:"order,omitempty"`
}
