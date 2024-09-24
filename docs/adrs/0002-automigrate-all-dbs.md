# ADR: All DBs should be automigrate - not just sqlite

Date: 2024-09-23

## Status

accepted

## Context

We were only automigrating the sqlite databases. When we added a column to the package table this broke the postgres scanner.

## Implementation

Enable automigrate for all databases supported.
