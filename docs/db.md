

# Database Schema Documentation

## Overview
This document provides an overview of the database schema used in the project. The database schema includes tables for packages, scans, vulnerabilities, and reports. The schema is designed to store information about software packages, their scans, and associated vulnerabilities.



``` mermaid
erDiagram
    PACKAGES {
        uint id PK
        string name
        string repository
        string tag
        time created_at
        time updated_at
    }
    
    SCANS {
        uint id PK
        int schema_version
        time created_at
        string artifact_name
        string artifact_type
        uint package_id FK
    }
    
    VULNERABILITIES {
        uint id PK
        uint scan_id FK
        string severity
        string description
    }
    
    PACKAGES ||--o{ SCANS : "has"
    SCANS ||--o{ VULNERABILITIES : "has"
```

## Tables

### 1. `packages`
Stores information about software packages.

**Columns:**
- `id` (uint, Primary Key): Unique identifier for the package.
- `name` (string): Name of the package.
- `repository` (string): Repository where the package is stored.
- `tag` (string): Tag associated with the package.
- `created_at` (time.Time): Timestamp when the package was created.
- `updated_at` (time.Time): Timestamp when the package was last updated.

### 2. `scans`
Stores information about scans performed on packages.

**Columns:**
- `id` (uint, Primary Key): Unique identifier for the scan.
- `schema_version` (int): Version of the scan schema.
- `created_at` (time.Time): Timestamp when the scan was created.
- `artifact_name` (string): Name of the artifact being scanned.
- `artifact_type` (string): Type of the artifact being scanned.
- `package_id` (uint, Foreign Key): Identifier of the package being scanned.
- `vulnerabilities` ([]Vulnerability): List of vulnerabilities found in the scan.

### 3. `vulnerabilities`
Stores information about vulnerabilities found in scans.

**Columns:**
- `id` (uint, Primary Key): Unique identifier for the vulnerability.
- `scan_id` (uint, Foreign Key): Identifier of the scan where the vulnerability was found.
- `severity` (string): Severity level of the vulnerability (e.g., HIGH, CRITICAL).
- `description` (string): Description of the vulnerability.


## Relationships
- A `package` can have multiple `scans`.
- A `scan` can have multiple `vulnerabilities`.
- A `report` is generated for a `package` and includes aggregated vulnerability data from its `scans`.

## Usage
This schema is used to store and manage data related to software package scans and their vulnerabilities. The relationships between tables ensure that each package can have multiple scans, and each scan can have multiple vulnerabilities. 
