package model

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// Scan represents the result of a vulnerability scan.
type Scan struct {
	Metadata        Metadata        `json:"Metadata" gorm:"embedded"`
	CreatedAt       time.Time       `json:"CreatedAt" gorm:"autoCreateTime"`
	UpdatedAt       time.Time       `json:"UpdatedAt" gorm:"autoUpdateTime"`
	ArtifactName    string          `json:"ArtifactName"`
	ArtifactType    string          `json:"ArtifactType"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities" gorm:"foreignKey:ScanID"`
	ID              uint            `json:"ID" gorm:"primaryKey;autoIncrement"`
	SchemaVersion   int             `json:"SchemaVersion"`
}

// Metadata contains additional information about the scanned artifact.
type Metadata struct {
	ImageConfig ImageConfig     `json:"ImageConfig" gorm:"embedded"`
	OS          OS              `json:"OS" gorm:"embedded"`
	ImageID     string          `json:"ImageID"`
	DiffIDs     JSONStringArray `json:"DiffIDs" gorm:"type:text"`
	RepoTags    JSONStringArray `json:"RepoTags" gorm:"type:text"`
	RepoDigests JSONStringArray `json:"RepoDigests" gorm:"type:text"`
}

// JSONStringArray custom type for handling JSON serialization of string arrays.
type JSONStringArray []string

// Value implements the driver.Valuer interface for database serialization.
func (j JSONStringArray) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil // Return nil if the array is empty
	}
	val, err := json.Marshal(j)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSONStringArray: %w", err)
	}
	return val, nil
}

// Scan implements the sql.Scanner interface for database deserialization.
func (j *JSONStringArray) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("JSONStringArray Scan error: expected []byte, got %T", value)
	}
	if err := json.Unmarshal(b, j); err != nil {
		return fmt.Errorf("failed to unmarshal JSONStringArray: %w", err)
	}
	return nil
}

// OS represents the operating system information.
type OS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

// ImageConfig contains the configuration details of the container image.
type ImageConfig struct {
	Config       Config    `json:"config" gorm:"embedded"`
	Architecture string    `json:"architecture"`
	Author       string    `json:"author"`
	Created      string    `json:"created"`
	OS           string    `json:"os"`
	RootFS       RootFS    `json:"rootfs" gorm:"embedded"`
	History      []History `json:"history" gorm:"type:text[]"`
}

// RootFS represents the root filesystem of the image.
type RootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids" gorm:"type:text[]"`
}

// Config represents the configuration of the container.
type Config struct {
	ExposedPorts ExposedPorts `json:"ExposedPorts" gorm:"type:jsonb"`
	User         string       `json:"User"`
	WorkingDir   string       `json:"WorkingDir"`
	Entrypoint   []string     `json:"Entrypoint" gorm:"type:text[]"`
	Env          []string     `json:"Env" gorm:"type:text[]"`
}

// ExposedPorts represents the exposed ports of the container.
type ExposedPorts map[string]interface{}

func (e ExposedPorts) Value() (driver.Value, error) {
	val, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ExposedPorts: %w", err)
	}
	return val, nil
}

func (e *ExposedPorts) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("ExposedPorts Scan error: expected []byte, got %T", value)
	}
	if err := json.Unmarshal(bytes, e); err != nil {
		return fmt.Errorf("failed to unmarshal ExposedPorts: %w", err)
	}
	return nil
}

type History struct {
	Author     string `json:"author,omitempty"`
	Created    string `json:"created"`
	CreatedBy  string `json:"created_by"`
	Comment    string `json:"comment"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
}

func (h History) Value() (driver.Value, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal History: %w", err)
	}
	return string(b), nil
}

func (h *History) Scan(value interface{}) error {
	b, ok := value.(string)
	if !ok {
		return fmt.Errorf("History Scan error: expected string, got %T", value)
	}
	if err := json.Unmarshal([]byte(b), h); err != nil {
		return fmt.Errorf("failed to unmarshal History: %w", err)
	}
	return nil
}
