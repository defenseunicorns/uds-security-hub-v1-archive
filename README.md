
# UDS Security Hub - Scan Package

_This is ALPHA and expect things to change._

- [Overview](#overview)
- [Usage](#usage)
- [Contributing](#contributing)

## Overview
The UDS Security Hub is a tool that helps you manage your `zarf` packages and scan them for vulnerabilities. It uses the Trivy vulnerability scanner to scan container images and extract relevant security information. It can be used to scan Zarf packages and generate CSV reports with the identified vulnerabilities.


The `pkg/scan` package provides functionality for scanning `zarf` packages and generating vulnerability reports.

## Usage

The main entry point is the `Scanner` struct, which provides the following methods:

1. `ScanZarfPackage(org, packageName, tag string)`: Scans a Zarf package and returns the scan results as a slice of file paths containing the JSON-formatted scan results.

2. `ScanResultReader(jsonFilePath string)`: Creates a new `ScanResultReader` from a JSON file containing the scan results. The `ScanResultReader` interface provides access to the scan results, including the ability to retrieve the artifact name, vulnerabilities, and generate a CSV report.

Here's an example of how to use the `ScanZarfPackage` method:

```go
scanner, err := scan.New(context.Background(), logger, "trivyUsername", "trivyPassword", "ghcrToken") // username and password to connect to example registry1
if err != nil {
    // Handle error
}

results, err := scanner.ScanZarfPackage("defenseunicorns", "packages/uds/gitlab-runner", "16.10.0-uds.0-upstream")
if err != nil {
    // Handle error
}

for _, v := range results {
    r, err := scanner.ScanResultReader(v)
    if err != nil {
        // Handle error
        continue
    }

    csv := r.GetResultsAsCSV()
    fmt.Println(csv)
}
```

This code creates a new `Scanner` instance, scans a Zarf package, and then generates a CSV report for each of the scan results.

## Contributing

If you find any issues or have suggestions for improvements, feel free to open an issue or submit a pull request on the project's repository.