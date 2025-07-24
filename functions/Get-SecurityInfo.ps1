<#
.SYNOPSIS
    Provides a comprehensive, consolidated security overview for one or more CVEs.

.DESCRIPTION
    This function acts as a "meta-function" that queries multiple security data sources for a given CVE ID.
    It gathers information from NVD, cve.org, CISA KEV, EPSS, and Exploit-DB, then presents a unified summary.

    The function intelligently prioritizes data sources, using the enriched information from NVD when available,
    but falling back to the official cve.org record for newer or reserved CVEs. This ensures the most
    complete and timely information is always returned.

.PARAMETER CveId
    One or more CVE IDs to query. These can be provided with or without the "CVE-" prefix.

.EXAMPLE
    PS C:\> Get-SecurityInfo -CveId "CVE-2024-21413"

    Retrieves the consolidated security information for the Microsoft Outlook vulnerability.

.EXAMPLE
    PS C:\> "2024-27198", "2024-27199" | Get-SecurityInfo

    Retrieves information for two different CVEs related to JetBrains TeamCity, using pipeline input.

.OUTPUTS
    [pscustomobject] An object containing a summarized view of the vulnerability, including its title, status,
    severity, and scores. It also includes detailed nested objects from each data source for deeper analysis.

.LINK
    https://nvd.nist.gov
    https://www.cve.org
    https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    https://www.first.org/epss/
    https://www.exploit-db.com/

.NOTES
    Author: Marco Kleinert
    Date: July 2025
#>
function Get-SecurityInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string[]]$CveId
    )

    process {
        $output =
        foreach ($id in $CveId) {
            $cve = $id
            if (-not $cve.StartsWith('CVE-', [System.StringComparison]::OrdinalIgnoreCase)) {
                $cve = "CVE-$cve"
            }

            $nvdData = Get-NvdCve -CveId $cve -ErrorAction SilentlyContinue
            $cveOrgData = Get-CveOrg -CveId $cve -ErrorAction SilentlyContinue
            $cisaData = Get-CisaKev -CveId $cve -ErrorAction SilentlyContinue
            $epssData = Get-EpssScore -CveId $cve -ErrorAction SilentlyContinue
            $exploitDbData = Get-ExploitDb -CveId $cve -ErrorAction SilentlyContinue
            $euvdData = Get-Euvd -CveId $cve -ErrorAction SilentlyContinue

            if ($null -eq $nvdData -and $null -eq $cveOrgData -and $null -eq $cisaData -and $null -eq $epssData -and $null -eq $exploitDbData -and $null -eq $euvdData) {
                Write-Warning "No information found for '$cve' in any of the available sources."
            }
            else {
                # Build the output object, prioritizing NVD, but falling back to CveOrg
                [pscustomobject][ordered]@{
                    CveId             = $cve
                    Title             = if ($cveOrgData) { $cveOrgData.Title } elseif ($nvdData) { $nvdData.Description } else { 'N/A' }
                    Published         = if ($nvdData) { $nvdData.Published } elseif ($cveOrgData) { $cveOrgData.DatePublished } else { 'N/A' }
                    LastModified      = if ($nvdData) { $nvdData.LastModified } elseif ($cveOrgData) { $cveOrgData.DateUpdated } else { 'N/A' }
                    Status            = if ($nvdData) { $nvdData.Status } elseif ($cveOrgData) { $cveOrgData.State } else { 'N/A' }
                    Severity          = if ($nvdData) { $nvdData.CVSSSeverity } elseif ($cveOrgData) { $cveOrgData.Severity } else { 'N/A' }
                    CVSSScore         = if ($nvdData) { $nvdData.CVSSBaseScore } elseif ($cveOrgData) { $cveOrgData.BaseScore } else { 'N/A' }
                    Description       = if ($nvdData) { $nvdData.Description } elseif ($cveOrgData) { $cveOrgData.Description } else { 'N/A' }
                    EPSS_Details      = if ($null -ne $epssData) { $epssData } else { $null }
                    ExploitDB_Details = if ($null -ne $exploitDbData) { $exploitDbData } else { $false }
                    CISA_KEV_Details  = if ($null -ne $cisaData) { $cisaData } else { $false }
                    NVD_Details       = if ($null -ne $nvdData) { $nvdData } else { $false }
                    CveOrg_Details    = if ($null -ne $cveOrgData) { $cveOrgData } else { $false }
                    EUVD_Details      = if ($null -ne $euvdData) { $euvdData } else { $false }
                }
            }
        }
        $output
    }
}
