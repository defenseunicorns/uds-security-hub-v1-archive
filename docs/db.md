
# Database Schema Documentation

## Overview
This document provides an overview of the database schema used in the project. The database schema includes tables for packages, scans, vulnerabilities, and reports. The schema is designed to store information about software packages, their scans, and associated vulnerabilities.

The `report` table serves as the external contract, while the `packages`, `scans`, and `vulnerabilities` tables are internal and used to store detailed data.

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
    
    REPORT {
        uint id PK
        time created_at
        string package_name
        string tag
        json sbom
        int critical
        int high
        int medium
        int low
        int info
        int total
    }
    
    PACKAGES ||--o{ SCANS : "has"
    SCANS ||--o{ VULNERABILITIES : "has"
    REPORT }|--|| PACKAGES : "aggregates"
```

## Tables

### 1. `packages` (Internal)
Stores information about software packages.

**Columns:**
- `id` (uint, Primary Key): Unique identifier for the package.
- `name` (string): Name of the package.
- `repository` (string): Repository where the package is stored.
- `tag` (string): Tag associated with the package.
- `created_at` (time.Time): Timestamp when the package was created.
- `updated_at` (time.Time): Timestamp when the package was last updated.

### 2. `scans` (Internal)
Stores information about scans performed on packages.

**Columns:**
- `id` (uint, Primary Key): Unique identifier for the scan.
- `schema_version` (int): Version of the scan schema.
- `created_at` (time.Time): Timestamp when the scan was created.
- `artifact_name` (string): Name of the artifact being scanned.
- `artifact_type` (string): Type of the artifact being scanned.
- `package_id` (uint, Foreign Key): Identifier of the package being scanned.
- `vulnerabilities` ([]Vulnerability): List of vulnerabilities found in the scan.

### 3. `vulnerabilities` (Internal)
Stores information about vulnerabilities found in scans.

**Columns:**
- `id` (uint, Primary Key): Unique identifier for the vulnerability.
- `scan_id` (uint, Foreign Key): Identifier of the scan where the vulnerability was found.
- `severity` (string): Severity level of the vulnerability (e.g., HIGH, CRITICAL).
- `description` (string): Description of the vulnerability.

### 4. `report` (External Contract)
Represents a report of a scan and serves as the external contract.

**Columns:**
- `id` (uint, Primary Key): Unique identifier for the report.
- `created_at` (time.Time): Timestamp when the report was created.
- `package_name` (string): Name of the package associated with the report.
- `tag` (string): Tag associated with the package.
- `sbom` (json.RawMessage): Software Bill of Materials (SBOM) data.
- `critical` (int): Count of critical vulnerabilities.
- `high` (int): Count of high vulnerabilities.
- `medium` (int): Count of medium vulnerabilities.
- `low` (int): Count of low vulnerabilities.
- `info` (int): Count of informational vulnerabilities.
- `total` (int): Total count of vulnerabilities.

## Relationships
- A `package` can have multiple `scans`.
- A `scan` can have multiple `vulnerabilities`.
- A `report` aggregates data from a `package` and its associated `scans` and `vulnerabilities`.

## Usage
This schema is used to store and manage data related to software package scans and their vulnerabilities. The relationships between tables ensure that each package can have multiple scans, and each scan can have multiple vulnerabilities. 

The `report` table serves as the external contract, providing a summary of the scan results for a package. It includes aggregated vulnerability counts and the SBOM data. The internal tables (`packages`, `scans`, and `vulnerabilities`) store the detailed data used to generate the reports.
```