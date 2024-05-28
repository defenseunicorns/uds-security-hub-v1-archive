package scan

/*
Package scan provides functionality for scanning container images and generating vulnerability reports.

The main functions and types in this package are:

ScanZarfPackage
    Scans a Zarf package and returns the scan results.

    Parameters:
        ctx: The context for the scan operation.
        org: The organization that owns the package.
        packageName: The name of the package to scan.
        githubToken: The GitHub token for authentication.
        trivyUsername: The username for Trivy authentication.
        trivyPassword: The password for Trivy authentication.
        tag: The tag of the package to scan.

    Returns:
        A slice of file paths containing the scan results in JSON format.
        An error if the scan operation fails.

NewScanResultReader
    Creates a new ScanResultReader from a JSON file.

    Parameters:
        jsonFilePath: The path to the JSON file containing the scan results.

    Returns:
        An instance of ScanResultReader that can be used to access the scan results.
        An error if the file cannot be opened or the JSON cannot be decoded.

ScanResultReader
    An interface that provides access to the scan results.

    GetArtifactName() string
        Returns the artifact name in the scan result.

    GetVulnerabilities() []types.VulnerabilityInfo
        Returns the vulnerabilities in the scan result.

    GetResultsAsCSV() string
        Returns the scan results in CSV format.

Example usage:

    results, err := scan.ScanZarfPackage(
        context.Background(),
        "defenseunicorns",
        "leapfrogai/rag",
        "my-github-token",
        "my-trivy-username",
        "my-trivy-password",
        "0.3.1",
    )
    if err != nil {
        // Handle error
    }

    reader, err := scan.NewScanResultReader("path/to/scanresult.json")
    if err != nil {
        // Handle error
    }

    artifactName := reader.GetArtifactName()
    vulnerabilities := reader.GetVulnerabilities()
    csvOutput := reader.GetResultsAsCSV()
    fmt.Println(csvOutput)
*/
