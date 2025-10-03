<#
.SYNOPSIS
    Aggregates and consolidates security information for one or more CVEs from multiple sources.

.DESCRIPTION
    This function serves as a central hub for vulnerability intelligence, querying multiple public security data sources for a given CVE ID. It gathers information from:
    - National Vulnerability Database (NVD)
    - CVE.org (MITRE)
    - CISA Known Exploited Vulnerabilities (KEV)
    - FIRST Exploit Prediction Scoring System (EPSS)
    - Exploit-DB
    - ENISA EU Vulnerability Database (EUVD)
    - GitHub Security Advisories

    The function then presents a unified summary, intelligently prioritizing data from the more detailed NVD source when available, but falling back to the official cve.org record for newer or reserved CVEs. This ensures the most complete and timely information is returned in a single, easy-to-use object.

.PARAMETER CveId
    One or more CVE IDs to query. These can be provided via direct parameter or through the pipeline.
    The 'CVE-' prefix is optional and will be added automatically.

.PARAMETER vulnDetails
    A switch parameter that, if specified, includes the full, detailed objects from each data source as nested properties in the output.
    The properties are named after the source (e.g., NVD_Data, CveOrg_Data, CisaKev_Data, etc.). This is useful for in-depth analysis.

.EXAMPLE
    Get-SecurityInfo -CveId "CVE-2024-21413"

    # Retrieves the consolidated security summary for the Microsoft Outlook vulnerability (CVE-2024-21413).

.EXAMPLE
    "2024-27198", "2024-27199" | Get-SecurityInfo

    # Retrieves information for two different CVEs related to JetBrains TeamCity using pipeline input.

.EXAMPLE
    Get-SecurityInfo -CveId "CVE-2023-36884" -vulnDetails

    # Retrieves the summary and also includes the full, detailed data objects from NVD, CISA KEV, Exploit-DB, and other sources where the CVE was found.

.OUTPUTS
    [pscustomobject]
    By default, returns an object containing a summarized view of the vulnerability with the following key fields:
    - CveId
    - Title, Published, LastModified, Status, Severity, CVSSScore, Description (prioritizing NVD, then CVE.org)
    - Boolean flags for quick checks (e.g., IsNvdAvailable, IsCisaKevAvailable, IsGitHubAvailable).

    If -vulnDetails is used, the object will also contain nested properties (e.g., NVD_Data, GitHub_Data) holding the complete objects from each respective source.

.LINK
    https://nvd.nist.gov
    https://www.cve.org
    https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    https://www.first.org/epss/
    https://www.exploit-db.com/
    https://euvd.enisa.europa.eu/
    https://docs.github.com/en/code-security/security-advisories

.NOTES
    Author: Marco Kleinert
    Date: July 2025
    This function calls other functions within the module. Ensure all function files are available.
    API keys for sources like GitHub must be configured for the underlying functions to work correctly.
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
