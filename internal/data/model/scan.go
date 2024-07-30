package model

import (
	"encoding/json"
	"time"
)

// Scan represents the result of a vulnerability scan.
type Scan struct {
	CreatedAt       time.Time       `json:"CreatedAt" gorm:"autoCreateTime"`
	UpdatedAt       time.Time       `json:"UpdatedAt" gorm:"autoUpdateTime"`
	ArtifactName    string          `json:"ArtifactName"`
	ArtifactType    string          `json:"ArtifactType"`
	Metadata        json.RawMessage `json:"Metadata" gorm:"type:jsonb"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities" gorm:"foreignKey:ScanID"`
	Entrypoint      json.RawMessage `json:"Entrypoint" gorm:"type:jsonb"`
	ID              uint            `json:"ID" gorm:"primaryKey;autoIncrement"`
	SchemaVersion   int             `json:"SchemaVersion"`
	PackageID       uint            `json:"PackageID"` // Foreign key to Package
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

// OS represents the operating system information.
type OS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

// ImageConfig contains the configuration details of the container image.
type ImageConfig struct {
	Config       Config       `json:"config" gorm:"embedded"`
	Architecture string       `json:"architecture"`
	Author       string       `json:"author"`
	Created      string       `json:"created"`
	OS           string       `json:"os"`
	RootFS       RootFS       `json:"rootfs" gorm:"embedded"`
	History      HistoryArray `json:"history" gorm:"type:jsonb"`
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

// History represents the history of the image.
type History struct {
	Author     string `json:"author,omitempty"`
	Created    string `json:"created"`
	CreatedBy  string `json:"created_by"`
	Comment    string `json:"comment"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
}

// HistoryArray is a custom type for handling JSON serialization of History arrays.
type HistoryArray []History
