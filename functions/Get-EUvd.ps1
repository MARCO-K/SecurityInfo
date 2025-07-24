<#
.SYNOPSIS
    Retrieves vulnerability information from the ENISA EU Vulnerability Database (EUVD) by ENISA ID or keyword.

.DESCRIPTION
    This function queries the ENISA EUVD API for vulnerability details using either an ENISA ID or a keyword. It returns information such as CVE ID, description, publication date, last modified date, severity, CVSS score, vector, and vendor.

.PARAMETER CveId
    The ENISA ID (e.g., "2023-12345") to retrieve vulnerability details for. The function will prepend 'EUVD-' if not present.

.PARAMETER Keyword
    A keyword to search for vulnerabilities in the ENISA EUVD database.

.EXAMPLE
    Get-Euvd -CveId "2023-12345"
    # Retrieves vulnerability details for ENISA ID 2023-12345.

.EXAMPLE
    Get-Euvd -Keyword "openssl"
    # Searches for vulnerabilities related to 'openssl' in the ENISA EUVD database.

.OUTPUTS
    [pscustomobject] containing vulnerability details for each matching entry.

.LINK
    https://euvd.enisa.europa.eu/

.NOTES
    Author: Marco Kleinert
    Date: July 2025
    The function uses the public ENISA EUVD API and may be subject to availability or rate limits.
#>
function Get-Euvd {

    [CmdletBinding(DefaultParameterSetName = 'ByCveId')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByCveId')]
        [string]$CveId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByKeyword')]
        [string]$Keyword

    )

    begin {
        $baseApiUrl = "https://euvdservices.enisa.europa.eu/api/"


        switch ($PSCmdlet.ParameterSetName) {
            'ByCveId' {
                if (-not $CveId.StartsWith('EUVD-', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $CveId = "EUVD-$CveId"
                }
                $apiUrl = "$($baseApiUrl)enisaid?id=$CveId"
            }
            'ByKeyword' {
                $apiUrl = "$($baseApiUrl)search?text=$Keyword"
            }
        }
    }
    process {
        try {
            $response = Invoke-RestMethod -Method Get -Uri $apiUrl
            Write-Verbose "Response from EUVD API: $apiUrl"
            if ($null -eq $response) {
                Write-Warning "No data found for '$CveId' or keyword '$Keyword'."
                return
            }
            if ($response.items.Count -ne 0) {
                $response = $response.items
            }
            $results =
            foreach ($item in $response) {

                [pscustomobject]@{
                    CveId        = $item.ID
                    Description  = $item.description
                    Published    = $item.datePublished
                    LastModified = $item.dateUpdated
                    Severity     = $item.severity
                    CVSSScore    = $item.baseScore
                    Vector       = $item.baseScoreVector
                    Vendor       = $response.enisaIdVendor.vendor.Name
                }
            }
            $results
        }
        catch {
            Write-Error "Failed to retrieve data from EUVD: $_"
        }
    }
}
