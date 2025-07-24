# SecurityInfo PowerShell Module

## Overview

SecurityInfo is a PowerShell module that provides functions to query and analyze security vulnerability data from public sources such as CVE.org, NVD, CISA KEV, Exploit-DB, and FIRST EPSS. It helps security professionals and researchers automate the retrieval and filtering of vulnerability information for threat intelligence, patch management, and reporting.

## Features

- Query CVEs from CVE.org API
- Query CVEs from the National Vulnerability Database (NVD)
- Retrieve known exploited vulnerabilities from CISA KEV
- Search for exploits in Exploit-DB by CVE
- Get EPSS scores for vulnerabilities from FIRST EPSS
- Filter results by severity, date, affected software, and more

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

### Aggregate Security Information from All Sources

```powershell
Get-SecurityInfo -CveId "2023-12345", "2023-12345", "2022-5678"
```

Retrieves and summarizes vulnerability information for one or more CVEs from NVD, CISA KEV, Exploit-DB, FIRST EPSS, and CveOrg.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Links

- [NVD JSON Feeds](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Exploit-DB](https://www.exploit-db.com/)
- [FIRST EPSS](https://www.first.org/epss/)
