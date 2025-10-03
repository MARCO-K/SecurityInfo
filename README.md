# SecurityInfo PowerShell Module

[![PSScriptAnalyzer](https://github.com/MARCO-K/SecurityInfo/actions/workflows/powershell.yml/badge.svg)](https://github.com/MARCO-K/SecurityInfo/actions/workflows/powershell.yml)

## Overview

SecurityInfo is a PowerShell module that provides a suite of functions to query, aggregate, and analyze security vulnerability data from multiple public sources. It is designed to help security professionals, researchers, and system administrators automate the retrieval of vulnerability intelligence for tasks like threat analysis, patch management, and reporting.

The core function, `Get-SecurityInfo`, consolidates data from all other functions to provide a single, comprehensive overview for a given CVE.

## Features

- **Aggregate View**: Get a consolidated security report for any CVE using `Get-SecurityInfo`.
- **NVD**: Query the National Vulnerability Database for detailed CVE information, including CVSS scores (v3.1 and v4.0), CPEs, and descriptions.
- **CVE.org**: Retrieve the official CVE record directly from the CVE Numbering Authority (CNA).
- **CISA KEV**: Check if a vulnerability is listed in the CISA Known Exploited Vulnerabilities catalog.
- **GitHub Advisories**: Fetch detailed security advisories directly from GitHub by CVE or GHSA ID.
- **EPSS**: Get Exploit Prediction Scoring System scores to gauge the likelihood of exploitation.
- **Exploit-DB**: Find publicly available exploits linked to a CVE.
- **ENISA EUVD**: Query the EU's vulnerability database for additional regional context.

## Requirements

- PowerShell 5.1 or later.
- **GitHub Personal Access Token (PAT)**: To use `Get-GitHubSecurityAdvisory` or `Get-SecurityInfo` for advisories, you must provide a GitHub PAT. Set it as an environment variable for convenience:
  ```powershell
  $env:GITHUB_PAT = "ghp_YourTokenHere"
  ```

## Installation

1.  Clone the repository:
    ```powershell
    git clone https://github.com/MARCO-K/SecurityInfo.git
    cd SecurityInfo
    ```
2.  Import the module into your PowerShell session:
    ```powershell
    Import-Module ./SecurityInfo.psd1
    ```

---

## Available Functions

This section details the primary functions available in the module.

### Get-SecurityInfo

This is the main function of the module. It aggregates data from all other sources to provide a single, comprehensive view of a vulnerability.

```powershell
# Get a summary view for a specific CVE
Get-SecurityInfo -CveId "CVE-2024-21413"

# Get a summary for multiple CVEs using the pipeline
"2024-27198", "2024-27199" | Get-SecurityInfo

# Get a detailed view, including the full data objects from each source
Get-SecurityInfo -CveId "CVE-2023-36884" -vulnDetails
```

### Get-NvdCve

Queries the National Vulnerability Database (NVD). This is often the most detailed source for CVSS scores and affected software configurations (CPEs).

```powershell
# Get CRITICAL CVEs published in the last 7 days
Get-NvdCve -Days 7 -Severity "CRITICAL"

# Search for CVEs related to "windows" and include affected software details
Get-NvdCve -Keyword "windows" -IncludeAffectedSoftware -Top 10
```

### Get-CveOrg

Retrieves the official CVE record from cve.org (MITRE). This is the authoritative source, especially for newly issued CVEs.

```powershell
# Get the official record for a specific CVE
Get-CveOrg -CveId "CVE-2024-0078"
```

### Get-CisaKev

Checks the CISA Known Exploited Vulnerabilities (KEV) catalog. Essential for prioritizing vulnerabilities that are actively being exploited.

```powershell
# Check if a specific CVE is in the KEV catalog
Get-CisaKev -CveId "2023-12345"

# Get vulnerabilities added to the KEV list in the last 7 days
Get-CisaKev -Days 7
```

### Get-GitHubSecurityAdvisory

Fetches detailed security advisories from GitHub. Requires a GitHub PAT.

```powershell
# Get an advisory by CVE ID
Get-GitHubSecurityAdvisory -CveId "2023-12345"

# Get an advisory by its unique GHSA ID
Get-GitHubSecurityAdvisory -GhsaId "GHSA-abcd-1234-efgh"
```

### Get-EpssScore

Retrieves the Exploit Prediction Scoring System (EPSS) score, which indicates the probability of a vulnerability being exploited in the wild.

```powershell
# Get the EPSS score for one or more CVEs
Get-EpssScore -CveId "2023-12345", "2022-5678"

# Find vulnerabilities with an EPSS score greater than 0.8 (80%)
Get-EpssScore -EpssGreaterThan 0.8
```

### Get-ExploitDb

Searches for public exploits in the Exploit-DB database.

```powershell
# Find exploits for a specific CVE
Get-ExploitDb -CveId "2023-12345"
```

### Get-Euvd

Queries the ENISA EU Vulnerability Database (EUVD).

```powershell
# Get vulnerability details by its CVE ID
Get-Euvd -CveId "2023-12345"

# Search for vulnerabilities related to 'openssl'
Get-Euvd -Keyword "openssl"
```

---

## Data Source Links

- [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
- [CVE.org Services API](https://cveawg.mitre.org/api-docs/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST EPSS API](https://www.first.org/epss/data-and-api)
- [Exploit-DB](https://www.exploit-db.com/)
- [ENISA EUVD API](https://euvd.enisa.europa.eu/apidoc)
- [GitHub Security Advisories API](https://docs.github.com/en/graphql)

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) to get started.

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.