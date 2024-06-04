# UDS Security Hub - Scan Package

[![Build and Test](https://github.com/defenseunicorns/uds-security-hub/actions/workflows/build.yaml/badge.svg)](https://github.com/defenseunicorns/uds-security-hub/actions/workflows/build.yaml)
[![E2E Tests](https://github.com/defenseunicorns/uds-security-hub/actions/workflows/test.yaml/badge.svg)](https://github.com/defenseunicorns/uds-security-hub/actions/workflows/test.yaml)
[![golangci-lint](https://github.com/defenseunicorns/uds-security-hub/actions/workflows/lint.yaml/badge.svg)](https://github.com/defenseunicorns/uds-security-hub/actions/workflows/lint.yaml)

[![Go Report Card](https://goreportcard.com/badge/github.com/defenseunicorns/uds-security-hub)](https://goreportcard.com/report/github.com/defenseunicorns/uds-security-hub)
[![codecov](https://codecov.io/gh/defenseunicorns/uds-security-hub/graph/badge.svg?token=WEEJUGX5VA)](https://codecov.io/gh/defenseunicorns/uds-security-hub)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/defenseunicorns/uds-security-hub/badge)](https://scorecard.dev/viewer/?uri=github.com/defenseunicorns/uds-security-hub)
[![Go Reference](https://pkg.go.dev/badge/github.com/defenseunicorns/uds-security-hub.svg)](https://pkg.go.dev/github.com/defenseunicorns/uds-security-hub)

_This is ALPHA and expect things to change._

_This depends on [trivy](https://github.com/aquasecurity/trivy) for vulnerability scanning and trivy has to be installed on the host._

## Table of Contents
- [Overview](#overview)
- [Usage](#usage)
- [Command Line Interface](#command-line-interface)
- [Contributing](#contributing)

## Overview
The UDS Security Hub is a tool designed to manage and scan `zarf` packages for vulnerabilities. It leverages the Trivy vulnerability scanner to analyze container images and extract security information, facilitating the generation of CSV reports detailing identified vulnerabilities.

## Usage

### Scanner Functionality
The `pkg/scan` package provides functionality for scanning `zarf` packages and generating vulnerability reports. The main entry point is the `Scanner` struct, which offers the following methods:

1. **ScanZarfPackage(org, packageName, tag string)**: Scans a Zarf package and returns the scan results as a slice of file paths containing the JSON-formatted scan results.
2. **ScanResultReader(jsonFilePath string)**: Initializes a new `ScanResultReader` from a JSON file containing the scan results. This interface allows access to the scan results, including retrieving the artifact name, vulnerabilities, and generating a CSV report.

#### Example Usage
```go
scanner, err := scan.New(context.Background(), logger, "dockerUsername", "dockerPassword") // Optional credentials for Docker registry access
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

### Command Line Interface
To run the scanner via the command line and generate a CSV output, use the `scan` command with the necessary flags:

```bash
scan -o [organization] -n [package-name] -g [tag] -u [docker-username] -p [docker-password] -f [output-file]
```

- `-o, --org`: Organization
- `-n, --package-name`: Package Name
- `-g, --tag`: Tag
- `-u, --docker-username`: (Optional) Docker username for registry access
- `-p, --docker-password`: (Optional) Docker password for registry access
- `-f, --output-file`: Output file for CSV results

**Example Command:**
```bash
scan -o defenseunicorns -n packages/uds/gitlab-runner -g 16.10.0-uds.0-upstream -u yourDockerUsername -p yourDockerPassword -f results.csv
```
![alt text](image.png)

### Running the Scanner using the Makefile

To effectively run the scanner using the Makefile, follow these improved and detailed steps:

1. **Open Your Terminal**: Access your command line interface. This could be Terminal on macOS, Command Prompt or PowerShell on Windows, or any terminal emulator on Linux.

2. **Navigate to the Project's Directory**: Change to the directory containing the project's source code. You can do this with the `cd` command:
   ```bash
   cd path/to/uds-security-hub
   ```

3. **Build the Scanner**: Compile the project to create an executable. This is done using the `build` target in the Makefile:
   ```bash
   make build
   ```
   This command will compile the code and generate an executable in the `bin/` directory.

4. **Run the Scanner**: Execute the scanner with the necessary parameters. Assuming the executable is named `uds-security-hub`, you would run:
   ```bash
   ./bin/uds-security-hub scan -o [organization] -n [package-name] -g [tag] -u [docker-username] -p [docker-password] -f [output-file]
   ```
   Replace the placeholders (e.g., `[organization]`, `[package-name]`) with actual values relevant to your scan.

5. **Verify the Output**: After executing the command, check the specified output file or directory for the CSV file containing the scan results. Ensure that the file `results.csv` has been created and contains the expected data.

These steps provide a clear and concise method to build and run the scanner using the Makefile, ensuring you are working with the most recent version of your tool.

## Contributing
If you encounter any issues or have suggestions for improvements, please feel free to open an issue or submit a pull request on the project's repository.
