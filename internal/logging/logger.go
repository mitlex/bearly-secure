package logging

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Logger struct {
	mutex sync.Mutex
	file  *os.File
	now   func() time.Time
}

var sensitiveFields = map[string]struct{}{
	"sessionId":   {},
	"resetToken":  {},
	"resetLink":   {},
	"secret":      {},
	"adminNotes":  {},
	"storagePath": {},
}

func Open(filePath string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open application log: %w", err)
	}
	return &Logger{file: file, now: time.Now}, nil
}

func (logger *Logger) Close() error {
	return logger.file.Close()
}

func (logger *Logger) Event(eventName string, fields map[string]any) error {
	record := map[string]any{
		"timestamp": logger.now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"event":     eventName,
	}
	redacted := make(map[string]any, len(fields))
	for name, value := range fields {
		if _, sensitive := sensitiveFields[name]; sensitive {
			redacted[name] = "[REDACTED]"
			continue
		}
		redacted[name] = value
	}
	maps.Copy(record, redacted)

	logger.mutex.Lock()
	defer logger.mutex.Unlock()
	if err := json.NewEncoder(logger.file).Encode(record); err != nil {
		return fmt.Errorf("write application log: %w", err)
	}
	return nil
}
