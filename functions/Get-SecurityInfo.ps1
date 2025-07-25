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

.PARAMETER vulnDetails
    If specified, includes detailed nested objects from each available data source in the output (NVD_Data, CveOrg_Data, CisaKev_Data, Epss_Data, ExploitDb_Data, Euvd_Data, GitHub_Data).

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
        [string[]]$CveId,
        [Parameter(Mandatory = $false)]
        [switch]$vulnDetails
    )

    process {
        $output =
        foreach ($id in $CveId) {
            $cve = $id
            if (-not $cve.StartsWith('CVE-', [System.StringComparison]::OrdinalIgnoreCase)) {
                $cve = "CVE-$cve"
            }

            # --- Gather all data up front ---
            $nvdData = Get-NvdCve -CveId $cve -ErrorAction SilentlyContinue
            $cveOrgData = Get-CveOrg -CveId $cve -ErrorAction SilentlyContinue
            $cisaData = Get-CisaKev -CveId $cve -ErrorAction SilentlyContinue
            $epssData = Get-EpssScore -CveId $cve -ErrorAction SilentlyContinue
            $exploitDbData = Get-ExploitDb -CveId $cve -ErrorAction SilentlyContinue
            $euvdData = Get-Euvd -CveId $cve -ErrorAction SilentlyContinue
            $githubAdvisoryData = Get-GitHubSecurityAdvisory -CveId $cve -ErrorAction SilentlyContinue

            if (-not ($nvdData, $cveOrgData, $cisaData, $epssData, $exploitDbData, $euvdData, $githubAdvisoryData).Where({ $null -ne $_ }, 'First')) {
                Write-Warning "No information found for '$cve' in any of the available sources."
                continue # Skip to the next CVE ID
            }
            else {
                # --- Build the output object using a single ordered hashtable for clarity and efficiency ---
                $props = [ordered]@{
                    CveId                = $cve
                    Title                = if ($cveOrgData) { $cveOrgData.Title } elseif ($nvdData) { $nvdData.Description } else { 'N/A' }
                    Published            = if ($nvdData) { $nvdData.Published } elseif ($cveOrgData) { $cveOrgData.DatePublished } else { 'N/A' }
                    LastModified         = if ($nvdData) { $nvdData.LastModified } elseif ($cveOrgData) { $cveOrgData.DateUpdated } else { 'N/A' }
                    Status               = if ($nvdData) { $nvdData.Status } elseif ($cveOrgData) { $cveOrgData.State } else { 'N/A' }
                    Severity             = if ($nvdData) { $nvdData.CVSSSeverity } elseif ($cveOrgData) { $cveOrgData.Severity } else { 'N/A' }
                    CVSSScore            = if ($nvdData) { $nvdData.CVSSBaseScore } elseif ($cveOrgData) { $cveOrgData.BaseScore } else { 'N/A' }
                    Description          = if ($nvdData) { $nvdData.Description } elseif ($cveOrgData) { $cveOrgData.Description } else { 'N/A' }

                    # --- Boolean flags for a quick summary view ---
                    IsNvdAvailable       = [bool]$nvdData
                    IsCveOrgAvailable    = [bool]$cveOrgData
                    IsCisaKevAvailable   = [bool]$cisaData
                    IsEpssAvailable      = [bool]$epssData
                    IsExploitDbAvailable = [bool]$exploitDbData
                    IsEuvdAvailable      = [bool]$euvdData
                    IsGitHubAvailable    = [bool]$githubAdvisoryData
                }

                # This block adds nested objects for each data source if -vulnDetails is used.
                if ($vulnDetails) {
                    # These are now independent 'if' statements, not an 'elseif' chain.
                    if ($nvdData) { $props['NVD_Data'] = $nvdData }
                    if ($cveOrgData) { $props['CveOrg_Data'] = $cveOrgData }
                    if ($cisaData) { $props['CisaKev_Data'] = $cisaData }
                    if ($epssData) { $props['Epss_Data'] = $epssData }
                    if ($exploitDbData) { $props['ExploitDb_Data'] = $exploitDbData }
                    if ($euvdData) { $props['Euvd_Data'] = $euvdData }
                    if ($githubAdvisoryData) { $props['GitHub_Data'] = $githubAdvisoryData }
                }
                # output the result object
                [pscustomobject]$props
            }
        }
        $output
    }
}
