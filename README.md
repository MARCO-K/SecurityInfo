# SecurityInfo PowerShell Module

## Overview

SecurityInfo is a PowerShell module that provides functions to query and analyze security vulnerability data from public sources such as CVE.org, NVD, CISA KEV, Exploit-DB, and FIRST EPSS. It helps security professionals and researchers automate the retrieval and filtering of vulnerability information for threat intelligence, patch management, and reporting.

![PSScriptAnalyzer](https://github.com/MARCO-K/SecurityInfo/actions/workflows/powershell.yml/badge.svg)

## Features

- Query CVEs from CVE.org API
- Query CVEs from the National Vulnerability Database (NVD)
- Query vulnerabilities from the ENISA EU Vulnerability Database (EUVD)
- Retrieve known exploited vulnerabilities from CISA KEV
- Search for exploits in Exploit-DB by CVE
- Get EPSS scores for vulnerabilities from FIRST EPSS
- Query GitHub Security Advisories by CVE or GHSA ID
- Filter results by severity, date, affected software, and more

### Query GitHub Security Advisories

```powershell
# By CVE ID
Get-GitHubSecurityAdvisory -CveId "2023-12345"

# By GHSA ID
Get-GitHubSecurityAdvisory -GhsaId "GHSA-xxxx-xxxx-xxxx"
```

Retrieves security advisory information from GitHub by CVE or GHSA ID. Requires a GitHub Personal Access Token (PAT) in the $env:GITHUB_PAT environment variable.

## Installation

1. Clone the repository:

    ```powershell
    git clone https://github.com/MARCO-K/SecurityInfo.git
    cd SecurityInfo
    ```

2. Import the module in PowerShell:

    ```powershell
    Import-Module "SecurityInfo"
    ```

## Usage Examples

### Get CVEs from NVD

```powershell
Get-NvdCve -Keyword "openssl" -Severity "HIGH" -Top 5
```

### Get CISA Known Exploited Vulnerabilities

```powershell
Get-CisaKev -Days 7
Get-CisaKev -CveId "2023-12345"
```

### Search Exploit-DB for Exploits

```powershell
Get-ExploitDb -CveId "2023-12345", "2023-12345", "2022-5678"
```

### Get EPSS Scores

```powershell
Get-EpssScore -CveId "2023-12345"
Get-EpssScore -Days 7
Get-EpssScore -EpssGreaterThan 0.5 -PercentileLessThan 0.9
```

### Query ENISA EU Vulnerability Database (EUVD)

```powershell
# By ENISA ID
Get-Euvd -CveId "2023-12345"

# By keyword
Get-Euvd -Keyword "openssl"
```

Retrieves vulnerability information from the ENISA EUVD by ENISA ID or keyword.

### Aggregate Security Information from All Sources

```powershell
# Summary view (with boolean flags for each source)
Get-SecurityInfo -CveId "2023-12345"

# Pipeline input
"2023-12345","2022-5678" | Get-SecurityInfo

# Include all available details from each source
Get-SecurityInfo -CveId "2023-12345" -vulnDetails
```

The summary view includes fields like Title, Status, Severity, and boolean flags (e.g., IsNvdAvailable, IsCisaKevAvailable, IsGitHubAvailable) to quickly see which sources have data. Use `-vulnDetails` to include full nested objects from each source (NVD_Data, CveOrg_Data, CisaKev_Data, Epss_Data, ExploitDb_Data, Euvd_Data, GitHub_Data).

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) to get started.

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Links

- [CVE.org API](https://www.cve.org/ResourcesSupport/Resources#CVEListDataFeeds)
- [NVD JSON Feeds](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Exploit-DB](https://www.exploit-db.com/)
- [FIRST EPSS](https://www.first.org/epss/)
- [ENISA EUVD](https://euvd.enisa.europa.eu/apidoc)
- [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories)
